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
	BridgeMode = "bridge"
	HostMode   = "host"
)

type ContainerMonitor struct {
	containerID string
	networkMode string
	pid         int
	uid         string // container uid
	cgroupPath  string
	ipt         *iptables.IPTables
}

func NewMonitor(containerID string, uid string) (*ContainerMonitor, error) {
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
		uid:         uid,
		ipt:         ipt,
	}

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
	//  iptables -A OUTPUT -m owner --uid-owner 1000
	if err := m.ipt.Insert("filter", "OUTPUT", 1, "-m", "owner", "--uid-owner", m.uid); err != nil {
		return err
	}

	return nil
}

// 清理规则
func (m *ContainerMonitor) Cleanup() {
	switch m.networkMode {
	case BridgeMode:
		panic("cleanup err: traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		err := m.ipt.Delete("mangle", "OUTPUT", "-m", "owner", "--uid-owner", m.uid)
		if err != nil {
			log.Printf("Delete OUTPUT Rule Error: %v", err)
		}
	}
}

func (m *ContainerMonitor) GetStats() (inBytes, outBytes uint64, err error) {
	switch m.networkMode {
	case BridgeMode:
		panic("not implemented")
		// return m.getBridgeStats()
	case HostMode:
		return m.getHostStats()
	default:
		return 0, 0, fmt.Errorf("unsupported network mode")
	}
}
func (m *ContainerMonitor) getHostStats() (uint64, uint64, error) {
	var totalIn, totalOut uint64

	rules, _ := m.ipt.ListWithCounters("filter", "OUTPUT")
	for _, rule := range rules {
		fmt.Printf("(OUTPUT)Rule: %s\n", rule)
		fmt.Printf("MATCH:[%v]\n", fmt.Sprintf("owner UID match %v", m.uid))
		//TODO: remove hard code of "cpu/docker_traffic"
		if strings.Contains(rule, fmt.Sprintf("owner UID match %v", m.uid)) {
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

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./monitor <container-id> <container-uid>")
		return
	}

	monitor, err := NewMonitor(os.Args[1], os.Args[2])
	// monitor, err := NewMonitor("1ed1c00b4e2d")
	if err != nil {
		log.Fatal(err)
	}
	defer monitor.Cleanup()

	if err := monitor.Setup(); err != nil {
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
		fmt.Printf("[%s] Traffic IN: %d bytes, OUT: %d bytes\n",
			time.Now().Format("15:04:05"), in, out)
	}
}
