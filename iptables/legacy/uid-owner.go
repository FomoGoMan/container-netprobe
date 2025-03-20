package legacy

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	general "github.com/FomoGoMan/container-netprobe/interface"
	helper "github.com/FomoGoMan/container-netprobe/pkg/iptables"
	helperuid "github.com/FomoGoMan/container-netprobe/pkg/uid"
	"github.com/cilium/ebpf/rlimit"

	"github.com/coreos/go-iptables/iptables"
)

const (
	BridgeMode   = "bridge"
	HostMode     = "host"
	networkTable = "filter"
)

var _ general.Collector = (*ContainerMonitor)(nil)
var _ general.SuspiciousDetector = (*ContainerMonitor)(nil)

type ContainerMonitor struct {
	containerID string
	networkMode string
	pid         int
	uid         int // container uid
	ipt         *iptables.IPTables
}

func NewMonitor(containerID string) (*ContainerMonitor, error) {
	if f, err := helper.IptablesSupportsOwnerUidMatch(); err != nil {
		return nil, fmt.Errorf("IptablesSupportsOwnerUidMatch failed: %v", err)
	} else if !f {
		return nil, fmt.Errorf("iptables owner uid match feature not supported")
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
		uid:         getUidOf(pid),
		ipt:         ipt,
	}
	log.Printf("Uid of container %v: %d\n", containerID, monitor.uid)

	switch mode {
	case BridgeMode:
		panic("traffic monitoring in bridge mod using iptables is not implemented")
	}

	return monitor, nil
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
		return m.setupHostRules()
	default:
		return fmt.Errorf("unsupported network mode: %s", m.networkMode)
	}
}

func (m *ContainerMonitor) setupHostRules() error {
	// out flow (upstream)
	if err := m.ipt.Insert(networkTable, "OUTPUT", 1, "-m", "owner", "--uid-owner", strconv.Itoa(m.uid), "-j", "ACCEPT"); err != nil {
		return err
	}

	return nil
}

func (m *ContainerMonitor) Cleanup() {
	switch m.networkMode {
	case BridgeMode:
		panic("cleanup err: traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		log.Printf("Deleting RULE...\n")
		err := m.ipt.Delete(networkTable, "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(m.uid), "-j", "ACCEPT", "--wait")
		if err != nil {
			log.Printf("Delete OUTPUT Rule Error: %v", err)
		}
	default:
		panic("unsupported network mode")
	}
}

func (m *ContainerMonitor) CollectTotal() (in, out uint64) {
	out, err := m.GetStats()
	if err != nil {
		log.Printf("Legacy GetStats Error: %v", err)
		return 0, 0
	}
	return 0, out
}

func (m *ContainerMonitor) GetStats() (outBytes uint64, err error) {
	switch m.networkMode {
	case BridgeMode:
		panic("not implemented")
	case HostMode:
		return m.getHostStats()
	default:
		return 0, fmt.Errorf("unsupported network mode")
	}
}

func (m *ContainerMonitor) getHostStats() (uint64, error) {
	var totalOut uint64

	rules, _ := m.ipt.ListWithCounters(networkTable, "OUTPUT")
	for _, rule := range rules {
		if strings.Contains(rule, fmt.Sprintf("--uid-owner %v", m.uid)) {
			fields := strings.Fields(rule)
			if len(fields) >= 9 {
				bytes, err := strconv.ParseUint(fields[8], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("failed to parse output bytes: %v", err)
				}
				totalOut += bytes
			}
		}
	}

	return totalOut, nil
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

func getUidOf(pid int) int {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "uid=")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 1 {
		uid, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0
		}
		return uid
	}
	return 0
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

	pidsGot, err := helperuid.GetPIDsByUID(m.uid)
	if err != nil {
		log.Printf("GetPidOfCgroup Error: %v\n", err)
		return err
	}
	pidWhiteList := []int{m.pid}
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
