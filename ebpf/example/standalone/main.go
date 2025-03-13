package main

import (
	traffic "ebpf_collector/general/monitor"
	"ebpf_collector/types"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// this code show ingress and egress traffic of all cgroup
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

func printStats(ingress types.FlowCgroup, egress types.FlowCgroup) {
	fmt.Println("\n=== Network Traffic Statistics ===")
	for cGroupId, flows := range ingress {
		fmt.Printf("CgroupId: %v\n", cGroupId)
		fmt.Printf(" Ingress:   %10d bytes\n", flows)
		fmt.Printf(" Egress:   %10d bytes\n", egress[cGroupId])
	}
	fmt.Println("================================")
}

func getCgroupID(path string) (uint64, error) {
	fileinfo, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("无法获取 inode 信息")
	}
	// cgroup ID 是 inode 号
	return stat.Ino, nil
}

func generateTestTraffic() {
	// 创建测试 Cgroup
	cgroupPath := "/sys/fs/cgroup/test_ebpf"
	if err := os.Mkdir(cgroupPath, 0755); err != nil && !os.IsExist(err) {
		log.Printf("create cgroup failed: %v", err)
		return
	}
	defer os.Remove(cgroupPath)

	// 获取 cgroup ID（关键代码）
	cgroupId, err := getCgroupID(cgroupPath)
	if err != nil {
		log.Printf("get cgroup id failed: %v", err)
		return
	}
	log.Printf("测试流量绑定的 cgroup ID: %d", cgroupId)

	// TCP IPv4 流量
	go func() {
		conn, err := net.Dial("tcp", "example.com:80")
		if err == nil {
			defer conn.Close()
			for i := 0; i < 5000000; i++ {
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
		for i := 0; i < 5000000; i++ {
			conn.Write([]byte("test payload"))
			time.Sleep(1 * time.Second)
		}
	}()

}
