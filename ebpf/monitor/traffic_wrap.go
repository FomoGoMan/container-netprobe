package monitor

import (
	"fmt"
	"log"

	general "github.com/FomoGoMan/container-netprobe/interface"
	helper "github.com/FomoGoMan/container-netprobe/pkg/container"
)

var _ general.Collector = (*ContainerEbpfMonitor)(nil)

type ContainerEbpfMonitor struct {
	monitor    *EBPFCollector
	cgroupPath string
	cgroupId   uint64
}

func NewEbpfCollector(containerID string) (*ContainerEbpfMonitor, error) {
	cgroupPath := helper.GetContainerInfo(containerID)
	fmt.Printf("CGroup Path: %v\n", cgroupPath)
	cgroupID, err := helper.GetCgroupID(cgroupPath)
	if err != nil {
		log.Printf("fail to get CGroup ID : %v", err)
		return nil, err
	}
	log.Printf("CGroup ID: %d\n", cgroupID)

	monitor, err := NewCollector()
	if err != nil {
		return nil, err
	}
	return &ContainerEbpfMonitor{
		monitor:    monitor,
		cgroupPath: cgroupPath,
		cgroupId:   cgroupID,
	}, nil
}

func (c *ContainerEbpfMonitor) CollectTotal() (in, out uint64) {
	return c.monitor.CollectTotal(c.cgroupId)
}

func (c *ContainerEbpfMonitor) SetUp() error {
	return c.monitor.load()
}

func (c *ContainerEbpfMonitor) Cleanup() {
	c.monitor.Close()
}
