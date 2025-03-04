package ebpf

import (
	"errors"
	"fmt"
	"go_minion/internal/build"
	"go_minion/internal/collector"
	"go_minion/internal/collector/ebpf/container"
	"go_minion/internal/collector/ebpf/host"
	"go_minion/internal/collector/types"
	"go_minion/internal/config"
	"go_minion/internal/datastore"
	"go_minion/internal/flowmanager"
	G "go_minion/internal/global"
	"go_minion/internal/report"
	"go_minion/pkg/logger"
	"os/exec"
	"strings"
	"time"

	kernel "github.com/shirou/gopsutil/v4/host"
	"golang.org/x/sys/unix"
)

const (
	validDuration = 5 * time.Minute
)

var (
	ErrInvalidData = errors.New("invalid data")
	ErrExpired     = errors.New("expired data")
)

func loadEbpfEnv() (collector.FlowCollector, error) {
	var rlim unix.Rlimit
	// 设置新的 RLIMIT_MEMLOCK 值为无限或者足够大的数值
	rlim.Cur = unix.RLIM_INFINITY
	rlim.Max = unix.RLIM_INFINITY
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		G.Logger.Warn("********** failed to set RLIMIT_MEMLOCK, %v", err)
		return nil, err
	}
	var eCollector collector.FlowCollector
	var err error
	if eCollector, err = newCollector(G.Logger); err != nil {
		G.Logger.Warn("start ebpf collector failed: %v", err)
		return nil, err
	}

	G.Logger.Info("start ebpf collector success")
	G.CurStrategy.Set(G.EBPF)
	return eCollector, nil
}

func getKernelVersion() (string, error) {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func Init() error {
	if !config.Global().Collect.UseEbpf {
		return fmt.Errorf("config close ebpf")
	}
	version, err := kernel.KernelVersion()
	if err != nil {
		return err
	}
	G.Logger.Info("kernel version: %v", version)
	for _, blackVersion := range config.Global().Collect.EbpfBlackKernel {
		if version == blackVersion {
			return fmt.Errorf("ebpf black kernel version [%s]", blackVersion)
		}
	}

	eCollector, err := loadEbpfEnv()
	if err != nil {
		// eBPF策略初始化失败
		return err
	}

	// eBPF策略初始化成功，运行eBPF采集
	ebpfDataStore := datastore.NewFileStore(G.EBPFLogPath, G.CfgMaxDuration, G.CfgMaxFileCount, "ebpf")
	efm := flowmanager.NewFlowManager("ebpf-flowmanager", eCollector, ebpfDataStore)
	efm.Run()

	// 游标指向数据时间小于最新上报时间时，更新数据上报游标
	// 目前只有appid涉及到两种策略上报，只更新appid游标
	/*
		数据示例:
		[root@x86 eminion]# cat ecursor_appid
		{
		    "file": "/xyapp/system/plugin-mdata/eminion/2024010221.log",
		    "pos": 7161
		}[root@x86 eminion]# cat ecursor_container
		{
		    "file": "/xyapp/system/plugin-mdata/eminion/2024010221.log",
		    "pos": 6475
		}
	*/

	// appid维度数据上报
	datastore.SynCursorFile(G.EBPFLogPath, "ecursor_appid", G.LatestAppidReportTime)
	ecursorAppid := ebpfDataStore.NewCursor("ecursor_appid")
	report.GetReporter().Init(ecursorAppid)
	err = report.GetReporter().Start()
	if err != nil {
		G.Logger.Error("start eBPF appid flow reporter error, exit! err: %v", err)
		return err
	}

	// x86平台 上报容器维度数据
	if build.IsXYKJ() {
		datastore.SynCursorFile(G.EBPFLogPath, "ecursor_container", G.LatestContainerReportTime)
		ecursorContainer := ebpfDataStore.NewCursor("ecursor_container")
		report.GetContainerFlowReporter().Init(ecursorContainer)
		err = report.GetContainerFlowReporter().Start()
		if err != nil {
			G.Logger.Error("start eBPF container flow reporter error, exit! err: %v", err)
			return err
		}
	}

	if config.Global().Collect.UseIPTables && config.Global().Collect.UseEbpf {
		// 定期上报ebpf跟iptables采集差异
		go flowmanager.DiffFlowReport()
	}
	return nil
}

type NetflowData struct {
	*types.FlowData
	ts time.Time
}

type Collector struct {
	lastData map[string]NetflowData
	logger   *logger.FieldLogger
	inner    types.Collector
}

func newCollector(fileLogger *logger.FileLogger) (collector.FlowCollector, error) {
	var inner types.Collector
	var err error
	if build.IsXYBM() {
		inner, err = host.NewCollector(fileLogger)
		if err != nil {
			return nil, err
		}
	} else {
		inner, err = container.NewCollector(fileLogger)
		if err != nil {
			return nil, err
		}
	}
	return &Collector{
		logger: logger.NewFieldLogger(fileLogger, "ebpf-collector"),
		inner:  inner,
	}, nil
}

func (r *Collector) GetFlowInfo() (map[string]*collector.FlowInfo, error) {
	resMap := make(map[string]*collector.FlowInfo)
	currentData := make(map[string]NetflowData)

	netflow := r.inner.Collect()
	if G.BinMode {
		containerId := G.BinModeID
		current := NetflowData{
			&types.FlowData{},
			time.Now(),
		}
		for _, flow := range netflow {
			for ind := 0; ind < len(flow); ind++ {
				current.FlowData[ind] += flow[ind]
			}
		}
		currentData[containerId] = current

		r.logger.Debug("cache ipv4 data, container[%s], L4TcpSend:%d, L4UdpSend:%d, L3TcpSend:%d, L3UdpSend:%d",
			containerId, current.FlowData[0], current.FlowData[2], current.FlowData[4], current.FlowData[5])
		r.logger.Debug("cache ipv6 data, container[%s], L4TcpSendV6:%d, L4UdpSendV6:%d, L3TcpSendV6:%d, L3UdpSendV6:%d",
			containerId, current.FlowData[7], current.FlowData[9], current.FlowData[11], current.FlowData[12])

		res, err := r.calcFlow(containerId, current.FlowData)
		if err == nil {
			r.logger.Info("containerId:%s {Tx:%d, Rx:%d, AppTx:%d, TxV6:%d, AppTxV6:%d}",
				containerId, res.TxFlow, res.RxFlow, res.AppTxFlow, res.TxFlowV6, res.AppTxFlowV6)
			resMap[containerId] = res
		} else {
			r.logger.Info("containerId:%s has no data, err:%v", containerId, err)
		}
	} else {
		for id, flow := range netflow {
			containerId := id
			currentData[containerId] = NetflowData{
				flow,
				time.Now(),
			}
			r.logger.Debug("cache ipv4 data, container[%s], L4TcpSend:%d, L4UdpSend:%d, L3TcpSend:%d, L3UdpSend:%d",
				containerId, flow[0], flow[2], flow[4], flow[5])
			r.logger.Debug("cache ipv6 data, container[%s], L4TcpSendV6:%d, L4UdpSendV6:%d, L3TcpSendV6:%d, L3UdpSendV6:%d",
				containerId, flow[7], flow[9], flow[11], flow[12])
			// 计算流量
			res, err := r.calcFlow(containerId, flow)
			if err != nil {
				r.logger.Error("containerId:%s has no data, err:%v", containerId, err)
				continue
			}
			// 日志示例: containerId:cf9445edc43fbf1610a65eee3e8f85308c75b5861d7fba26d89fede19387f6ca, txflow:703686448, rxflow:5838078417, appTxflow:448801839, TxFlowV6:1616799, AppTxFlowV6:944585
			r.logger.Info("containerId:%s {Tx:%d, Rx:%d, AppTx:%d, TxV6:%d, AppTxV6:%d}",
				containerId, res.TxFlow, res.RxFlow, res.AppTxFlow, res.TxFlowV6, res.AppTxFlowV6)
			resMap[containerId] = res
		}
	}
	r.lastData = currentData
	return resMap, nil
}

func (r *Collector) calcFlow(containerId string, current *types.FlowData) (*collector.FlowInfo, error) {
	lastData, ok := r.lastData[containerId]
	if !ok {
		lastData = NetflowData{FlowData: &types.FlowData{}}
	} else {
		// 判断时间是否有效
		if time.Since(lastData.ts) > validDuration {
			return nil, ErrExpired
		}

		// 判断数据是否有效(后面采集的值一定会比前面的大)
		for i := 0; i < len(lastData.FlowData); i++ {
			if lastData.FlowData[i] > current[i] {
				r.logger.Error("container:%s last.%s > current.%s: %d > %d", containerId, types.FlowIndexToTypeMap[i], types.FlowIndexToTypeMap[i], lastData.FlowData[i], current[i])
				return nil, ErrInvalidData
			}
		}
	}

	// 计算差值
	tx_v4 := (current[4] + current[5]) - (lastData.FlowData[4] + lastData.FlowData[5])
	tx_v6 := (current[11] + current[12]) - (lastData.FlowData[11] + lastData.FlowData[12])
	apptx_v4 := (current[0] + current[2]) - (lastData.FlowData[0] + lastData.FlowData[2])
	apptx_v6 := (current[7] + current[9]) - (lastData.FlowData[7] + lastData.FlowData[9])
	rx := (current[1] + current[3] + current[8] + current[10]) -
		(lastData.FlowData[1] + lastData.FlowData[3] + lastData.FlowData[8] + lastData.FlowData[10])
	return &collector.FlowInfo{
		TxFlow:      tx_v4 + tx_v6,
		TxFlowV6:    tx_v6,
		AppTxFlow:   apptx_v4 + apptx_v6,
		AppTxFlowV6: apptx_v6,
		RxFlow:      rx,
	}, nil
}
