package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

const (
	BridgeMode   = "bridge"
	HostMode     = "host"
	networkTable = "filter"
)

type ContainerMonitor struct {
	containerID string
	networkMode string
	pid         int
	uid         int // container uid
	cgroupPath  string
	ipt         *iptables.IPTables
}

func NewMonitor(containerID string) (*ContainerMonitor, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	mode, err := getNetworkMode(containerID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Network mode: %s of container %v\n", mode, containerID)

	pid, err := getContainerPID(containerID)
	if err != nil {
		return nil, err
	}
	fmt.Printf("PID: %d of container %v\n", pid, containerID)

	monitor := &ContainerMonitor{
		containerID: containerID,
		networkMode: mode,
		pid:         pid,
		uid:         getUidOf(pid),
		ipt:         ipt,
	}
	fmt.Printf("Uid of container %v: %d\n", containerID, monitor.uid)

	switch mode {
	case BridgeMode:
		panic("traffic monitoring in bridge mod using iptables is not implemented")
	}

	return monitor, nil
}

func (m *ContainerMonitor) Setup() error {

	m.Cleanup()

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
		err := m.ipt.Delete(networkTable, "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(m.uid), "-j", "ACCEPT")
		if err != nil {
			log.Printf("Delete OUTPUT Rule Error: %v", err)
		}
	}
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
	fmt.Printf("Raw Network mode: %s of container %v\n", mode, containerID)
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./monitor <container-id> ")
		return
	}

	monitor, err := NewMonitor(os.Args[1])
	// monitor, err := NewMonitor("1ed1c00b4e2d")
	if err != nil {
		log.Fatal(err)
	}
	defer monitor.Cleanup()

	if err := monitor.Setup(); err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		out, err := monitor.GetStats()
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		fmt.Printf("[%s]  OUT: %d bytes\n",
			time.Now().Format("15:04:05"), out)
	}
}
