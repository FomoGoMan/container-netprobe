package main

import (
	"ebpf_collector/ebpf/monitor"
	mytypes "ebpf_collector/types"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

func getCgroupID(cgroupPath string) (uint64, error) {
	// 1. 获取 cgroup 路径的文件信息
	fileInfo, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}

	// 2. 提取 inode 号（类型为 uint64）
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("无法获取 inode 信息")
	}

	// 3. inode 号即为 cgroup ID（内核行为）
	return stat.Ino, nil
}
func main() {
	// 1. 启动测试容器 (Host/Bridge 模式均可)
	containerID := startContainer()
	defer stopContainer(containerID)
	fmt.Printf("目标容器 ID: %s\n", containerID)

	// 2. 获取容器的 CGroup ID
	cgroupPath := getContainerInfo(containerID)
	fmt.Printf("目标容器 CGroup Path: %v\n", cgroupPath)
	cgroupID, err := getCgroupID(cgroupPath)
	if err != nil {
		log.Fatalf("获取 CGroup ID 失败: %v", err)
	}
	fmt.Printf("CGroup ID: %d\n", cgroupID)

	// 3. 加载并挂载 监控程序
	collector, err := monitor.NewCollector()
	if err != nil {
		log.Fatalf("error new collector %v", err)
		return
	}

	// 4. 持续打印流量统计
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		in, out := collector.Collect()
		printStats(in, out, cgroupID)
	}
}

// 启动测试容器并返回容器 ID
func startContainer() string {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "example",
	}, nil, nil, nil, "")
	if err != nil {
		log.Fatal(err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		log.Fatal(err)
	}
	return resp.ID
}

// 停止容器
func stopContainer(containerID string) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	_ = cli.ContainerRemove(ctx, containerID, container.RemoveOptions{})
}

func getContainerInfo(containerID string) (cgroupPath string) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.48"))
	if err != nil {
		log.Fatal(err)
	}

	// 获取容器详细信息
	info, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		log.Fatal(err)
	}

	// 从容器信息中直接获取 CGroup 路径
	cgroupPath = info.HostConfig.CgroupParent
	if cgroupPath == "" {
		// 若使用 cgroup v2，路径可能需要拼接
		cgroupPath = fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", info.ID)
	}
	log.Printf("CGroup Path: %s", cgroupPath)
	return
}

func printStats(ingress mytypes.FlowCgroup, egress mytypes.FlowCgroup, cgroupID uint64) {
	fmt.Println("\n=== Network Traffic Statistics ===")
	for cGroupId, flows := range ingress {
		if cGroupId != cgroupID {
			continue
		}
		fmt.Printf(" Ingress:   %10d bytes\n", flows)
		fmt.Printf(" Egress:   %10d bytes\n", egress[cGroupId])
	}
	fmt.Println("================================")
}
