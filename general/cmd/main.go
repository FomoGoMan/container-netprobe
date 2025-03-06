package main

import (
	traffic "ebpf_collector/general/monitor"
	"ebpf_collector/types"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	// 初始化流量采集器
	collector, err := traffic.NewCollector()
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}
	defer collector.Close()

	// 启动流量生成器
	go generateTestTraffic()

	// 定时输出统计信息
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// 处理退出信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			printStats(collector.Collect())
		case <-sig:
			fmt.Println("\nExiting...")
			return
		}
	}
}

func printStats(flowMap types.FlowCgroup) {
	fmt.Println("\n=== Network Traffic Statistics ===")
	for cGroupId, flows := range flowMap {
		fmt.Printf("CgroupId: %v\n", cGroupId)
		fmt.Printf("  All InCome :   %10d bytes\n", flows)
	}
	fmt.Println("================================")
}

func generateTestTraffic() {
	// 创建测试 Cgroup
	cgroupPath := "/sys/fs/cgroup/test_ebpf"
	if err := os.Mkdir(cgroupPath, 0755); err != nil && !os.IsExist(err) {
		log.Printf("create cgroup failed: %v", err)
		return
	}
	defer os.Remove(cgroupPath)

	// 将当前进程加入 Cgroup
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		log.Printf("write cgroup.procs failed: %v", err)
		return
	}

	// TCP IPv4 流量
	go func() {
		conn, err := net.Dial("tcp", "example.com:80")
		if err == nil {
			defer conn.Close()
			for i := 0; i < 5; i++ {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
				time.Sleep(1 * time.Second)
			}
		}
	}()

	// UDP IPv4 流量
	go func() {
		addr, _ := net.ResolveUDPAddr("udp4", "8.8.8.8:53")
		conn, _ := net.DialUDP("udp4", nil, addr)
		defer conn.Close()
		for i := 0; i < 5; i++ {
			conn.Write([]byte("test payload"))
			time.Sleep(1 * time.Second)
		}
	}()

}
