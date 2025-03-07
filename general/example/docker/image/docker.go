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
