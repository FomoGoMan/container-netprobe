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

func NewGeneralCollectorWithSetUp(containerId string) (*GeneralCollector, error) {
	// linux 5.10+, ebpf
	collector, err := monitor.NewEbpfCollector(containerId)
	if err == nil {
		if err = collector.SetUp(); err == nil {
			log.Printf("[Using eBPF] for container: %s\n", containerId)
			return &GeneralCollector{
				collector:   collector,
				containerId: containerId,
			}, nil
		}
		log.Printf("ebpf setup error: %v\n", err)
	}
	log.Printf("eBPF collector not supported, try other collector, error creating %v\n", err)

	// linux 4.x, iptables + cgroup v1/v2
	collectorIpt, err := modern.NewMonitor(containerId)
	if err == nil {
		if err = collector.SetUp(); err == nil {
			log.Printf("[Using iptables modern] for container: %s\n", containerId)
			return &GeneralCollector{
				collector:   collectorIpt,
				containerId: containerId,
			}, nil
		}
		log.Printf("iptables modern setup error: %v\n", err)
	}
	log.Printf("iptables modern collector not supported, error creating collector %v\n", err)

	// linux 3.x iptables + uid owner
	collectorLgc, err := legacy.NewMonitor(containerId)
	if err == nil {
		if err = collectorLgc.SetUp(); err == nil {
			log.Printf("[Using iptables legacy] for container: %s\n", containerId)
			return &GeneralCollector{
				collector:   collectorLgc,
				containerId: containerId,
			}, nil
		}
		log.Printf("iptables legacy setup error: %v\n", err)
	}
	log.Printf("iptables legacy collector not supported, error creating collector %v\n", err)

	panic("no collector supported for this system")
}

func (c *GeneralCollector) EnableSuspiciousDetect() {
	detection, err := c.collector.EnableSuspiciousDetect()
	if err != nil {
		panic(err)
	}
	go func() {
		for pid := range detection {
			log.Printf("WARN: Suspicious pid detected: %d, Stopping collecting traffic value\n", pid)
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
