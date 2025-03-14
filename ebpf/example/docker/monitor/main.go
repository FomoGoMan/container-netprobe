package main

import (
	"fmt"
	"log"
	"time"

	"github.com/FomoGoMan/container-netprobe/ebpf/monitor"
	helper "github.com/FomoGoMan/container-netprobe/pkg/container"
	mytypes "github.com/FomoGoMan/container-netprobe/types"
)

func main() {
	// 1. 启动测试容器 (Host/Bridge 模式均可)
	containerID := helper.StartContainer()
	defer helper.StopContainer(containerID)
	log.Printf("目标容器 ID: %s\n", containerID)

	// 2. 获取容器的 CGroup ID
	cgroupPath := helper.GetContainerInfo(containerID)
	fmt.Printf("目标容器 CGroup Path: %v\n", cgroupPath)
	cgroupID, err := helper.GetCgroupID(cgroupPath)
	if err != nil {
		log.Fatalf("获取 CGroup ID 失败: %v", err)
	}
	log.Printf("CGroup ID: %d\n", cgroupID)

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
