package monitor

import (
	"ebpf_collector/types"
	"ebpf_collector/utility"
	"fmt"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 traffic ebpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 traffic ebpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm traffic ebpf.c

type Collector struct {
	objs  ebpfObjects
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

	if err := load(&c.objs, nil); err != nil {
		return err
	}

	return nil
}

func (c *Collector) Close() {
	for _, link := range c.links {
		link.Close()
	}
	c.objs.Close()
}

func (c *Collector) Collect() types.FlowMap {
	flows := make(types.FlowMap)
	cpus := utility.GetNumOfPossibleCpus()

	flow := make(types.FlowData)
	m := c.objs.NetworkFlowMap
	for _, key := range types.AllFlowTypes {
		values := make([]uint64, cpus)
		if err := m.Lookup(&key, &values); err == nil {
			flow[key] = utility.Sum(values)
		} else {
			fmt.Printf("lookup %d failed: %v", key, err)
		}
	}

	container := "000000000000"
	flows[container] = &flow
	return flows
}
