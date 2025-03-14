package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/FomoGoMan/container-netprobe/iptables/legacy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./monitor <container-id> ")
		return
	}

	monitor, err := legacy.NewMonitor(os.Args[1])

	if err != nil {
		log.Fatal(err)
	}
	defer monitor.Cleanup()

	if err := monitor.SetUp(); err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		out, err := monitor.GetStats()
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		fmt.Printf("[%s]  OUT: %d bytes\n",
			time.Now().Format("15:04:05"), out)
	}
}
