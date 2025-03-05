package main

import (
	traffic "ebpf_collector/host/v2"
	"ebpf_collector/types"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
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

func printStats(flowMap types.FlowMap) {
	fmt.Println("\n=== Network Traffic Statistics ===")
	for container, flows := range flowMap {
		fmt.Printf("Container: %s\n", container)
		fmt.Printf("  TCP Upload (IPv4):   %10d bytes\n", (*flows)[uint32(types.L4_TCP_SEND_V4)])
		fmt.Printf("  TCP Download (IPv4): %10d bytes\n", (*flows)[uint32(types.L4_TCP_RECV_V4)])
		fmt.Printf("  UDP Upload (IPv4):   %10d bytes\n", (*flows)[uint32(types.L4_UDP_SEND_V4)])
		fmt.Printf("  UDP Download (IPv4): %10d bytes\n", (*flows)[uint32(types.L4_UDP_RECV_V4)])
		fmt.Printf("  TCP Upload (IPv6):   %10d bytes\n", (*flows)[uint32(types.L4_TCP_SEND_V6)])
		fmt.Printf("  TCP Download (IPv6): %10d bytes\n", (*flows)[uint32(types.L4_TCP_RECV_V6)])
		fmt.Printf("  UDP Upload (IPv6):   %10d bytes\n", (*flows)[uint32(types.L4_UDP_SEND_V6)])
		fmt.Printf("  UDP Download (IPv6): %10d bytes\n", (*flows)[uint32(types.L4_UDP_RECV_V6)])
	}
	fmt.Println("================================")
}

func generateTestTraffic() {
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

	// TCP IPv6 流量（需要系统支持）
	go func() {
		conn, err := net.Dial("tcp6", "[2606:2800:220:1:248:1893:25c8:1946]:80")
		if err == nil {
			defer conn.Close()
			for i := 0; i < 3; i++ {
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
				time.Sleep(1 * time.Second)
			}
		} else {
			log.Printf("IPv6 test failed: %v (may not be supported)", err)
		}
	}()
}
