package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	go generateTestTraffic()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-sig:
			fmt.Println("\nExiting...")
			return
		}
	}
}

func generateTestTraffic() {
	go func() {
		// TCP
		conn, err := net.Dial("tcp", "example.com:80")
		if err == nil {
			defer conn.Close()
			req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
			for { // 减少循环次数便于测试
				time.Sleep(1 * time.Second)
				_, err = conn.Write(req)
				if err != nil {
					break
				}
				// 读取响应
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf) // 简单示例，需处理错误
				// print response as readable string
				fmt.Println(string(buf[:n]))
				_ = n // 实际统计时累加 n
			}
		}
	}()
	// UDP
	go func() {
		addr, _ := net.ResolveUDPAddr("udp4", "8.8.8.8:53")
		conn, _ := net.DialUDP("udp4", nil, addr)
		defer conn.Close()
		req := []byte("test payload")
		for {
			time.Sleep(1 * time.Second)
			_, _ = conn.Write(req)
			// 读取响应
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf) // 简单示例，需处理错误
			_ = n                  // 实际统计时累加 n
		}
	}()
}
