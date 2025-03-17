package collector

import (
	"log"

	"github.com/FomoGoMan/container-netprobe/ebpf/monitor"
	general "github.com/FomoGoMan/container-netprobe/interface"
	"github.com/FomoGoMan/container-netprobe/iptables/legacy"
	modern "github.com/FomoGoMan/container-netprobe/iptables/morden"
)

type GeneralCollector struct {
	collector   general.CollectorWithFraudDetect
	containerId string
	stopCollect bool
}

func (c *GeneralCollector) CollectTotal() (in uint64, out uint64) {
	if c.stopCollect {
		return 0, 0
	}
	return c.collector.CollectTotal()
}

func NewGeneralCollector(containerId string) (*GeneralCollector, error) {
	// linux 5.10+, ebpf
	collector, err := monitor.NewEbpfCollector(containerId)
	if err == nil {
		if err == nil {
			log.Printf("[Using eBPF]containerId: %s\n", containerId)
			return &GeneralCollector{
				collector:   collector,
				containerId: containerId,
			}, nil
		}
		log.Printf("GetCgroupID Error: %v\n", err)
	}
	log.Printf("eBPF collector not supported, try other collector, error %v\n", err)

	// linux 4.x, iptables + cgroup v1/v2
	collectorIpt, err := modern.NewMonitor(containerId)
	if err == nil {
		log.Printf("[Using iptables modern]containerId: %s\n", containerId)
		return &GeneralCollector{
			collector:   collectorIpt,
			containerId: containerId,
		}, nil
	}
	log.Printf("iptables modern collector not supported, try other collector, error %v\n", err)

	// linux 3.x iptables + uid owner
	collectorLgc, err := legacy.NewMonitor(containerId)
	if err == nil {
		log.Printf("[Using iptables legacy]containerId: %s\n", containerId)
		return &GeneralCollector{
			collector:   collectorLgc,
			containerId: containerId,
		}, nil
	}

	panic("no collector supported for this system")
}

func (c *GeneralCollector) WithSuspiciousDetect() {
	detection, err := c.collector.EnableSuspiciousDetect()
	if err != nil {
		panic(err)
	}
	go func() {
		for pid := range detection {
			log.Printf("Suspicious pid: %d\n", pid)
			c.stopCollect = true
		}
	}()

	return
}

func (c *GeneralCollector) Cleanup() {
	c.collector.Cleanup()
}

func (c *GeneralCollector) SetUp() error {
	return c.collector.SetUp()
}
