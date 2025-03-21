package morden

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	general "github.com/FomoGoMan/container-netprobe/interface"
	helpercg "github.com/FomoGoMan/container-netprobe/pkg/cgroup"
	helperIpt "github.com/FomoGoMan/container-netprobe/pkg/iptables"
	"github.com/cilium/ebpf/rlimit"
	"github.com/opencontainers/runtime-spec/specs-go"

	cg "github.com/containerd/cgroups/v3"
	cgroupsv1 "github.com/containerd/cgroups/v3/cgroup1"
	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/coreos/go-iptables/iptables"
)

// 思路：使用 cgroup v2 分配流量统计
// 1. 创建一个 cgroup 并绑定容器, eg. docker_traffic
// mkdir -p /sys/fs/cgroup/docker_traffic
// echo $$ > /sys/fs/cgroup/docker_traffic/cgroup.procs
// 2.然后用 iptables 统计特定 cgroup
// iptables -t mangle -I OUTPUT -m cgroup --path docker_traffic
// iptables -t mangle -I INPUT -m cgroup --path docker_traffic
// 这样 docker_traffic 内的进程（包括容器进程）会被统计
// NOTE：直接使用容器自身的cgroup会有很多额外的进程加入cgroup，导致统计不准确
// NOTE: 使用 mangle表，勿使用filters表因为docker或者k8s有时会在你前面插入规则，并且统计会被重置
// 依赖：iptables -m cgroup --path 需要 iptables 1.8.0+ 和 Linux 4.8+

const (
	BridgeMode = "bridge"
	HostMode   = "host"
)

var _ general.Collector = (*ContainerMonitor)(nil)
var _ general.CGroupInfoGetter = (*ContainerMonitor)(nil)
var _ general.PidInfoGetter = (*ContainerMonitor)(nil)
var _ general.SuspiciousDetector = (*ContainerMonitor)(nil)

type ContainerMonitor struct {
	containerID string
	networkMode string
	pid         int
	cGroupPath  string

	ipt           *iptables.IPTables
	cgroupManager *cgroupsv2.Manager // v2
	control       cgroupsv1.Cgroup   // v1
}

func NewMonitor(containerID string) (*ContainerMonitor, error) {
	// check iptables feature support -m cgroup --path
	if pass, err := helperIpt.IptablesSupportsCgroupPath(); err != nil {
		return nil, err
	} else if !pass {
		return nil, fmt.Errorf("iptables cgroup path match not supported, iptables version too low")
	}

	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	mode, err := getNetworkMode(containerID)
	if err != nil {
		return nil, err
	}
	log.Printf("Network mode: %s of container %v\n", mode, containerID)

	pid, err := getContainerPID(containerID)
	if err != nil {
		return nil, err
	}
	if pid == 0 {
		return nil, fmt.Errorf("pid of container %v is 0, container may stopped", containerID)
	}
	log.Printf("PID: %d of container %v\n", pid, containerID)

	monitor := &ContainerMonitor{
		containerID: containerID,
		networkMode: mode,
		pid:         pid,
		ipt:         ipt,
	}

	switch mode {
	case BridgeMode:
		panic("traffic monitoring in bridge mod using iptables is not implemented")
	}

	return monitor, nil
}

func getNetworkMode(containerID string) (string, error) {
	cmd := exec.Command("docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", containerID)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	mode := strings.TrimSpace(string(out))
	log.Printf("Raw Network mode: %s of container %v\n", mode, containerID)
	if mode == "default" || mode == "bridge" {
		return BridgeMode, nil
	}
	return HostMode, nil
}

func getContainerPID(containerID string) (int, error) {
	cmd := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func getCustomCgroupName(container string) string {
	return fmt.Sprintf("docker_probe_%s", container)
}

func (m *ContainerMonitor) bindContainerToCgroup(containerPID string, containerID string) error {
	pid, err := strconv.ParseInt(containerPID, 10, 64)
	if err != nil {
		return err
	}
	// v2
	if m.cgroupManager != nil {
		m.cgroupManager.AddProc(uint64(pid))
		return nil
	}
	// v1
	if m.control != nil {
		return m.control.Add(cgroupsv1.Process{Pid: int(pid)}, cgroupsv1.Name("cpu"))
	}
	return fmt.Errorf("got unexpected both nil cgroup manager for v1 and v2")
}

func (m *ContainerMonitor) SetUp() error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("ContainerMonitor Modern Removing memlock: %v", err)
	}
	switch m.networkMode {
	case BridgeMode:
		panic("traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		err := m.createCgroup(m.containerID)
		if err != nil {
			log.Printf("Error creating cgroup: %v\n", err)
			return err
		}
		err = m.bindContainerToCgroup(strconv.Itoa(m.pid), m.containerID)
		if err != nil {
			log.Printf("Error binding container to cgroup: %v\n", err)
			return err
		}
		return m.setupHostRules()
	default:
		return fmt.Errorf("unsupported network mode: %s", m.networkMode)
	}
}

func (m *ContainerMonitor) createCgroup(containerID string) error {
	// cgroup v2
	if cg.Mode() == cg.Unified || cg.Mode() == cg.Hybrid {
		var cgroupManager *cgroupsv2.Manager
		res := cgroupsv2.Resources{}
		cgroupManager, err := cgroupsv2.NewManager("/sys/fs/cgroup/", "/"+getCustomCgroupName(containerID), &res)
		if err != nil {
			log.Printf("Error creating cgroup: %v\n", err)
			return err
		}
		m.cgroupManager = cgroupManager
		m.cGroupPath = filepath.Join("/sys/fs/cgroup/", getCustomCgroupName(containerID))
		log.Printf("The group created successfully, version [v2] path %v\n", m.cGroupPath)
		return nil
	}

	// cgroup v1
	shares := uint64(100)
	control, err := cgroupsv1.New(cgroupsv1.StaticPath("/test"), &specs.LinuxResources{
		CPU: &specs.LinuxCPU{
			Shares: &shares,
		},
	})
	if err != nil {
		return err
	}
	m.control = control
	m.cGroupPath = filepath.Join("/sys/fs/cgroup/cpu/", getCustomCgroupName(containerID))
	log.Printf("The group created successfully, version [v1] path %v\n", m.cGroupPath)
	return nil
}

func (m *ContainerMonitor) setupHostRules() error {
	prefix := "cpu/"
	if cg.Mode() == cg.Unified {
		prefix = ""
	}

	// In flow (downstream)
	if err := m.ipt.Insert("mangle", "INPUT", 1, "-m", "cgroup", "--path", prefix+getCustomCgroupName(m.containerID)); err != nil {
		return err
	}

	// out flow (upstream)
	if err := m.ipt.Insert("mangle", "OUTPUT", 1, "-m", "cgroup", "--path", prefix+getCustomCgroupName(m.containerID)); err != nil {
		return err
	}

	return nil
}

func (m *ContainerMonitor) Cleanup() {
	prefix := "cpu/"
	if cg.Mode() == cg.Unified {
		prefix = ""
	}

	switch m.networkMode {
	case BridgeMode:
		panic("cleanup err: traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		err := m.ipt.Delete("mangle", "INPUT", "-m", "cgroup", "--path", prefix+getCustomCgroupName(m.containerID))
		if err != nil {
			log.Printf("Delete INPUT Rule Error: %v", err)
		}
		err = m.ipt.Delete("mangle", "OUTPUT", "-m", "cgroup", "--path", prefix+getCustomCgroupName(m.containerID))
		if err != nil {
			log.Printf("Delete OUTPUT Rule Error: %v", err)
		}
	}

	// TODO: delete cgroup after container stopped
	// defer m.control.Delete()
}

func (m *ContainerMonitor) GetStats() (inBytes, outBytes uint64, err error) {
	switch m.networkMode {
	case BridgeMode:
		panic("not implemented")
	case HostMode:
		return m.getHostStats()
	default:
		return 0, 0, fmt.Errorf("unsupported network mode")
	}
}

func (m *ContainerMonitor) CollectTotal() (in, out uint64) {
	in, out, err := m.GetStats()
	if err != nil {
		log.Printf("GetStats Error: %v", err)
		return 0, 0
	}
	return in, out
}

func (m *ContainerMonitor) getHostStats() (uint64, uint64, error) {
	prefix := "cpu/"
	if cg.Mode() == cg.Unified {
		prefix = ""
	}

	var totalIn, totalOut uint64
	rules, _ := m.ipt.ListWithCounters("mangle", "INPUT")
	for _, rule := range rules {
		// fmt.Printf("(INPUT)Rule: %s\n", rule)
		if strings.Contains(rule, prefix+getCustomCgroupName(m.containerID)) {
			fields := strings.Fields(rule)
			if len(fields) >= 9 {
				bytes, err := strconv.ParseUint(fields[8], 10, 64)
				if err != nil {
					return 0, 0, fmt.Errorf("failed to parse input bytes: %v", err)
				}
				totalIn += bytes
			}
		}
	}

	rules, _ = m.ipt.ListWithCounters("mangle", "OUTPUT")
	for _, rule := range rules {
		// fmt.Printf("(OUTPUT)Rule: %s\n", rule)
		if strings.Contains(rule, prefix+getCustomCgroupName(m.containerID)) {
			fields := strings.Fields(rule)
			if len(fields) >= 9 {
				bytes, err := strconv.ParseUint(fields[8], 10, 64)
				if err != nil {
					return 0, 0, fmt.Errorf("failed to parse output bytes: %v", err)
				}
				totalOut += bytes
			}
		}
	}

	return totalIn, totalOut, nil
}

func (m *ContainerMonitor) GetCgroupPath() string {
	return m.cGroupPath
}

func (m *ContainerMonitor) GetPid() int {
	return m.pid
}

// launch a goroutine to monitor suspicious process that not in white list
func (m *ContainerMonitor) EnableSuspiciousDetect() (suspicious chan int, err error) {
	suspicious = make(chan int, 1)
	err = m.suspiciousDetectOnce(suspicious)
	go func() {
		for {
			time.Sleep(5 * time.Second)
			m.suspiciousDetectOnce(suspicious)
		}
	}()
	return
}

func (m *ContainerMonitor) suspiciousDetectOnce(suspicious chan int) (err error) {
	if m.GetCgroupPath() == "" {
		return fmt.Errorf("cgroup path is empty, hit: make sure you call `SetUp()` first before `EnableSuspiciousDetect`")
	}

	pidsGot, err := helpercg.GetPidOfCgroup(filepath.Join(m.GetCgroupPath(), "cgroup.procs"))
	if err != nil {
		log.Printf("GetPidOfCgroup Error: %v\n", err)
		return err
	}
	pidWhiteList := []int{m.GetPid()}
	// TODO: may be allow of pid parent pid belongs to
	for _, whitePid := range pidWhiteList {
		for _, pid := range pidsGot {
			if pid == whitePid {
				continue
			}
			suspicious <- pid
			return nil
		}
	}
	return nil
}
