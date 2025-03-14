package collector

import (
	"fmt"

	"github.com/FomoGoMan/container-netprobe/ebpf/monitor"
	"github.com/FomoGoMan/container-netprobe/general"
	"github.com/FomoGoMan/container-netprobe/iptables/legacy"
	modern "github.com/FomoGoMan/container-netprobe/iptables/morden"
	helper "github.com/FomoGoMan/container-netprobe/pkg/container"
)

type GeneralCollector struct {
	general.Collector
	containerId string
	cgroupId    uint64
}

func (c *GeneralCollector) CGroupId() uint64 {
	return c.cgroupId
}

func NewGeneralCollector(containerId string) (*GeneralCollector, error) {
	// linux 5.10+, ebpf
	collector, err := monitor.NewCollector()
	if err == nil {
		cgroupId, err := helper.GetCgroupID(helper.GetContainerInfo(containerId))
		if err == nil {
			fmt.Printf("[Using eBPF]containerId: %s, cgroupId: %d\n", containerId, cgroupId)
			return &GeneralCollector{
				Collector:   collector,
				containerId: containerId,
				cgroupId:    cgroupId,
			}, nil
		}
	}
	fmt.Println("eBPF collector not supported, try other collector, error %v\n", err)

	// linux 4.x, iptables + cgroup v2
	collectorIpt, err := modern.NewMonitor(containerId)
	if err == nil {
		fmt.Printf("[Using iptables modern]containerId: %s\n", containerId)
		return &GeneralCollector{
			Collector:   collectorIpt,
			containerId: containerId,
			cgroupId:    0, // not used
		}, nil
	}
	fmt.Printf("iptables modern collector not supported, try other collector, error %v\n", err)

	// linux 3.x iptables + uid owner
	collectorLgc, err := legacy.NewMonitor(containerId)
	if err == nil {
		fmt.Printf("[Using iptables legacy]containerId: %s\n", containerId)
		return &GeneralCollector{
			Collector:   collectorLgc,
			containerId: containerId,
			cgroupId:    0, // not used
		}, nil
	}

	panic("no collector supported this system")
}

func (c *GeneralCollector) Cleanup() {
	c.Collector.Cleanup()
}
