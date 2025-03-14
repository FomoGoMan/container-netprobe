package morden

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/FomoGoMan/container-netprobe/general"
	helper "github.com/FomoGoMan/container-netprobe/pkg/iptables"

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

// 依赖：iptables version

const (
	BridgeMode = "bridge"
	HostMode   = "host"
)

var _ general.Collector = (*ContainerMonitor)(nil)

type ContainerMonitor struct {
	containerID        string
	networkMode        string
	pid                int
	ipt                *iptables.IPTables
	cgroupManager      *cgroupsv2.Manager // v2
	control            cgroupsv1.Cgroup   // v1
	cgroupRelativePath string
}

func NewMonitor(containerID string) (*ContainerMonitor, error) {
	// check iptables feature support -m cgroup --path
	if pass, err := helper.IptablesSupportsCgroupPath(); err != nil {
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

func (m *ContainerMonitor) createCgroup(containerID string) error {
	// cgroup v2
	if cg.Mode() == cg.Unified {
		var cgroupManager *cgroupsv2.Manager
		res := cgroupsv2.Resources{}
		cgroupManager, err := cgroupsv2.NewManager("/sys/fs/cgroup/", getCustomCgroupName(containerID), &res)
		if err != nil {
			log.Printf("Error creating cgroup: %v\n", err)
			return err
		} else {
			log.Println("The group created successfully")
		}
		m.cgroupManager = cgroupManager
		return nil
	}

	// cgroup v1
	control, err := cgroupsv1.New(cgroupsv1.StaticPath("/"+getCustomCgroupName(containerID)), nil)
	if err != nil {
		return err
	}
	m.control = control
	return nil
}

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func getCustomCgroupName(container string) string {
	return fmt.Sprintf("docker_probe_%s", container)
}

func (m *ContainerMonitor) bindContainerToCgroup(containerPID string, containerID string) error {
	pid, err := strconv.ParseInt(containerPID, 10, 64)
	if err != nil {
		return err
	}

	if m.cgroupManager != nil {
		m.cgroupManager.AddProc(uint64(pid))
	}
	return m.control.Add(cgroupsv1.Process{Pid: int(pid)}, cgroupsv1.Name("cpu"))
}

func (m *ContainerMonitor) SetUp() error {
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

func (m *ContainerMonitor) setupHostRules() error {
	// In flow (downstream)
	if err := m.ipt.Insert("mangle", "INPUT", 1, "-m", "cgroup", "--path", "cpu/"+getCustomCgroupName(m.containerID)); err != nil {
		return err
	}

	// out flow (upstream)
	if err := m.ipt.Insert("mangle", "OUTPUT", 1, "-m", "cgroup", "--path", "cpu/"+getCustomCgroupName(m.containerID)); err != nil {
		return err
	}

	return nil
}

func (m *ContainerMonitor) Cleanup() {
	switch m.networkMode {
	case BridgeMode:
		panic("cleanup err: traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		err := m.ipt.Delete("mangle", "INPUT", "-m", "cgroup", "--path", "cpu/"+getCustomCgroupName(m.containerID))
		if err != nil {
			log.Printf("Delete INPUT Rule Error: %v", err)
		}
		err = m.ipt.Delete("mangle", "OUTPUT", "-m", "cgroup", "--path", "cpu/"+getCustomCgroupName(m.containerID))
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

func (m *ContainerMonitor) CollectTotal(cgroupId uint64) (in, out uint64) {
	in, out, err := m.GetStats()
	if err != nil {
		log.Printf("GetStats Error: %v", err)
		return 0, 0
	}
	return in, out
}

func (m *ContainerMonitor) getHostStats() (uint64, uint64, error) {
	var totalIn, totalOut uint64

	rules, _ := m.ipt.ListWithCounters("mangle", "INPUT")
	for _, rule := range rules {
		// fmt.Printf("(INPUT)Rule: %s\n", rule)
		//TODO: remove hard code string "cpu/docker_traffic"
		if strings.Contains(rule, "cpu/docker_traffic") {
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
		//TODO: remove hard code string "cpu/docker_traffic"
		if strings.Contains(rule, "cpu/docker_traffic") {
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

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage: ./monitor <container-id>")
		return
	}

	monitor, err := NewMonitor(os.Args[1])

	if err != nil {
		log.Fatal(err)
	}
	defer monitor.Cleanup()

	if err := monitor.SetUp(); err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		in, out, err := monitor.GetStats()
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		log.Printf("[%s] Traffic IN: %d bytes, OUT: %d bytes\n",
			time.Now().Format("15:04:05"), in, out)
	}
}
