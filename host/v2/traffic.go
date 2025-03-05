package traffic

import (
	"ebpf_collector/types"
	"ebpf_collector/utility"
	"fmt"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go-target amd64 traffic traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 traffic traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm traffic traffic.c

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
	if err := loadTrafficObjects(&c.objs, nil); err != nil {
		return err
	}

	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitTcpSendpage}); err != nil {
		return err
	} else {
		c.links["fexit/tcp_sendpage"] = link
	}

	// TCP-SEND
	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitTcpSendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/tcp_sendmsg"] = link
	}

	// TCP-RECV
	if link, err := link.Kprobe("tcp_cleanup_rbuf", c.objs.KprobeTcpCleanupRbuf, nil); err != nil {
		return err
	} else {
		c.links["kprobe/tcp_cleanup_rbuf"] = link
	}

	// UDP-SEND-IPv4
	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitUdpSendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/udp_sendmsg"] = link
	}

	// UDP-SEND-IPv6
	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitUdpv6Sendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/udpv6_sendmsg"] = link
	}

	// UDP-RECV
	if link, err := link.Kprobe("skb_consume_udp", c.objs.KprobeSkbConsumeUdp, nil); err != nil {
		return err
	} else {
		c.links["kprobe/skb_consume_udp"] = link
	}

	// L3-SEND-IPv4
	if link, err := link.Kprobe("ip_output", c.objs.KprobeIpOutput, nil); err != nil {
		return err
	} else {
		c.links["kprobe/ip_output"] = link
	}

	// L3-SEND-IPv6
	if link, err := link.Kprobe("ip6_output", c.objs.KprobeIp6Output, nil); err != nil {
		return err
	} else {
		c.links["kprobe/ip6_output"] = link
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

	var flow types.FlowData
	m := c.objs.NetworkFlowMap
	for key := uint32(0); key < 14; key++ {
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
