package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

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

type ContainerMonitor struct {
	containerID string // 容器ID
	networkMode string // 网络模式
	pid         int    // 容器进程PID
	cgroupPath  string
	ipt         *iptables.IPTables
}

// 创建监控器
func NewMonitor(containerID string) (*ContainerMonitor, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}

	// 获取容器基础信息
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
		ipt:         ipt,
	}

	// err = createCGroupEnsureCommand(getCustomCgroupName(containerID))
	// if err != nil {
	// 	fmt.Printf("Failed to create cgroup: %v, target %v\n", err, getCustomCgroupName(containerID))
	// 	return nil, err
	// }

	// 根据网络模式初始化参数
	switch mode {
	case BridgeMode:
		panic("traffic monitoring in bridge mod using iptables is not implemented")
	case HostMode:
		if err := bindContainerToCgroup(strconv.Itoa(pid), containerID); err != nil {
			return nil, err
		}
		panic("success")
	}

	return monitor, nil
}

func createCGroupEnsureCommand(cgroupPath string) error {
	// 检查 cgcreate 是否存在
	if !commandExists("cgcreate") {
		fmt.Println("cgcreate not found, installing cgroup-tools...")
		if err := installCgroupTools(); err != nil {
			fmt.Printf("Failed to install cgroup-tools: %v\n", err)
			return err
		}
	}

	// 使用 cgcreate 创建 cgroup
	if err := createCgroup(cgroupPath); err != nil {
		fmt.Printf("Failed to create cgroup: %v\n", err)
		return err
	}

	fmt.Println("Cgroup created successfully!")
	return nil
}

// 检查命令是否存在
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func installCgroupTools() error {
	// Ubuntu
	cmd := exec.Command("apt-get", "install", "-y", "cgroup-tools")
	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to install cgroup-tools using apt install, try yum: %v\n", err)
	}
	// ​CentOS/RHEL
	cmd = exec.Command("yum", "install", "-y", "libcgroup-tools")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install cgroup-tools: %v", err)
	}
	return nil
}

// 使用 cgcreate 创建 cgroup
func createCgroup(path string) error {
	cmd := exec.Command("cgcreate", "-g", "cpu:/"+path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cgcreate failed: %v", err)
	}
	return nil
}

func getCustomCgroupPath(container string) string {
	return "/sys/fs/cgroup/cpu/docker_traffic"
	// return fmt.Sprintf("/sys/fs/cgroup/cpu/%s/", getCustomCgroupName(container))
}

func getCustomCgroupName(container string) string {
	return "docker_traffic"
	// return fmt.Sprintf("Monitor_Docker_%v", container)
}

func bindContainerToCgroup(containerPID string, containerID string) error {
	cmd := exec.Command("cgcreate", "-g", fmt.Sprintf("cpu:/%s", getCustomCgroupName(containerID)))
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		fmt.Printf("cgcreate error: %v, Stderr: %s, stdout: %s\n", err, stderr.String(), stdout.String())
		return err
	}

	cmd = exec.Command("sh", "-c", fmt.Sprintf("echo %s > %s/cgroup.procs", containerPID, getCustomCgroupPath(containerID)))
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error: %v, Stderr: %s, Stdout: %s\n", err, stderr.String(), stdout.String())
		return err
	}

	return nil
}

// 设置监控规则
func (m *ContainerMonitor) Setup() error {
	// 清理旧规则
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
	// In flow (downstream)
	if err := m.ipt.Insert("mangle", "INPUT", 1, "-m", "cgroup", "--path", getCustomCgroupPath(m.containerID)); err != nil {
		return err
	}

	// out flow (upstream)
	// if err := m.ipt.Insert("filter", "OUTPUT", 1, "-m", "owner", "--path", getCustomCgroupPath(m.containerID)); err != nil {
	if err := m.ipt.Insert("filter", "OUTPUT", 1, "-m", "cgroup", "--path", getCustomCgroupPath(m.containerID)); err != nil {
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
		err := m.ipt.Delete("mangle", "INPUT", "-m", "cgroup", "--path", getCustomCgroupPath(m.containerID))
		if err != nil {
			log.Printf("Delete INPUT Rule Error: %v", err)
		}
		err = m.ipt.Delete("mangle", "OUTPUT", "-m", "cgroup", "--path", getCustomCgroupPath(m.containerID))
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

	rules, _ := m.ipt.ListWithCounters("mangle", "INPUT")
	for _, rule := range rules {
		fmt.Printf("(INPUT)Rule: %s\n", rule)
		if strings.Contains(rule, m.containerID) {
			fields := strings.Fields(rule)
			if len(fields) >= 8 {
				in, _, _ := parseCounter(fields[1])
				totalIn += in
			}
		}
	}

	rules, _ = m.ipt.ListWithCounters("mangle", "OUTPUT")
	for _, rule := range rules {
		fmt.Printf("(OUTPUT)Rule: %s\n", rule)
		if strings.Contains(rule, m.containerID) {
			fields := strings.Fields(rule)
			if len(fields) >= 8 {
				_, out, _ := parseCounter(fields[1])
				totalOut += out
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

func parseCounter(s string) (uint64, uint64, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid counter format")
	}
	in, _ := strconv.ParseUint(parts[0], 10, 64)
	out, _ := strconv.ParseUint(parts[1], 10, 64)
	return in, out, nil
}

// 示例用法
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./monitor <container-id>")
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
