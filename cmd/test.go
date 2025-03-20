package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	collector "github.com/FomoGoMan/container-netprobe"
)

func main() {
	// usage ./main <container id>
	if len(os.Args) < 2 {
		log.Println("Usage: ./main <container-id>")
		return
	}

	containerID := os.Args[1]
	log.Printf("Target Container ID: %s\n", containerID)

	monitor, err := collector.NewGeneralCollectorWithSetUp(containerID)
	if err != nil {
		log.Println(err)
		return
	}
	defer monitor.Cleanup()

	// optional
	suspiciousPid := monitor.EnableSuspiciousDetect()

	go func() {
		for {
			in, out := monitor.CollectTotal()
			log.Printf("In: %d bytes, Out: %d bytes\n", in, out)
			time.Sleep(2 * time.Second)
		}
	}()

	go func() {
		for pid := range suspiciousPid {
			log.Printf("WARN: Suspicious pid detected: %d\n", pid)
		}
	}()

	// wait ctrl-c
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
