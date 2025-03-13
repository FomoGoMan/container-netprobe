package collector

import (
	"ebpf_collector/ebpf/monitor"
	"ebpf_collector/general"
	"ebpf_collector/iptables/legacy"
	modern "ebpf_collector/iptables/morden"
	helper "ebpf_collector/pkg/container"
	"fmt"
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
	fmt.Println("eBPF collector not supported, try other collector")

	// linux 4.x, iptables + cgroup v2
	collectorIpt, err := modern.NewMonitor(containerId)
	if err == nil {
		fmt.Printf("[Using iptables]containerId: %s\n", containerId)
		return &GeneralCollector{
			Collector:   collectorIpt,
			containerId: containerId,
			cgroupId:    0, // not used
		}, nil
	}

	// linux 3.x iptables + uid owner
	collectorLgc, err := legacy.NewMonitor(containerId)
	if err == nil {
		fmt.Printf("[Using iptables]containerId: %s\n", containerId)
		return &GeneralCollector{
			Collector:   collectorLgc,
			containerId: containerId,
			cgroupId:    0, // not used
		}, nil
	}

	panic("no collector supported this system")
}
