package monitor

import (
	"ebpf_collector/types"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 traffic ebpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 traffic ebpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm traffic ebpf.c

type Collector struct {
	objs  trafficObjects
	links map[string]link.Link
}

func NewCollector() (*Collector, error) {
	c := &Collector{
		links: make(map[string]link.Link),
	}
	if err := c.load(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Collector) load() error {
	// coll, err := ebpf.LoadCollection("ebpf.o")
	// if err != nil {
	// 	log.Fatalf("加载 eBPF 失败: %v", err)
	// }

	// // 挂载到根 CGroup (监控所有流量)
	// rootCgroup := "/sys/fs/cgroup"
	// l, err := link.AttachCgroup(link.CgroupOptions{
	// 	Path:    rootCgroup,
	// 	Program: coll.Programs["cgroup_ingress"],
	// 	Attach:  ebpf.AttachCGroupInetIngress,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// return &bpfObjects{
	// 	cgroup_stats: coll.Maps["cgroup_stats"],
	// 	Programs:     []*ebpf.Program{l.Program()},
	// }

	// Load pre-compiled programs and maps into the kernel.

	if err := loadTrafficObjects(&c.objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
		return err
	}
	defer c.objs.Close()

	// Get the first-mounted cgroupv2 path.
	// cgroupPath, err := detectCgroupPath()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// Link the count_egress_packets program to the cgroup.
	// // 挂载到根 CGroup (监控所有流量)
	rootCgroup := "/sys/fs/cgroup"
	if l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    rootCgroup,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: c.objs.CgroupEgress,
	}); err != nil {
		log.Fatal(err)
		return err
	} else {
		c.links["cgroup_skb/egress"] = l
	}

	return nil
}

func (c *Collector) Close() {
	for _, link := range c.links {
		link.Close()
	}
	c.objs.Close()
}

func (c *Collector) Collect() types.FlowCgroup {
	flows := make(types.FlowCgroup)
	var key, value uint64

	iter := c.objs.CgroupStats.Iterate()
	if iter.Next(&key, &value) {
		flows[key] += value
	}

	return flows
}
