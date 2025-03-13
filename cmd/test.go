package main

import (
	collector "ebpf_collector"
	"fmt"
	"os"
	"time"
)

func main() {
	// usage ./main <container id>
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./main <container-id>")
		return
	}

	containerID := os.Args[1]
	fmt.Printf("Target Container ID: %s\n", containerID)

	monitor, err := collector.NewGeneralCollector(containerID)
	if err != nil {
		fmt.Println(err)
		return
	}
	go func() {
		in, out := monitor.CollectTotal(monitor.CGroupId())
		fmt.Printf("Ingress: %d bytes, Egress: %d bytes\n", in, out)
		time.Sleep(2 * time.Second)
	}()
}
