package traffic

import (
	"go_minion/internal/collector/types"
	"go_minion/pkg/logger"
	"go_minion/pkg/utility"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 traffic traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 traffic traffic.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm traffic traffic.c

type Collector struct {
	logger *logger.FieldLogger
	objs   trafficObjects
	links  map[string]link.Link
}

func NewCollector(fileLogger *logger.FileLogger) (*Collector, error) {
	c := &Collector{
		logger: logger.NewFieldLogger(fileLogger, "ebpf-host-v1"),
		links:  make(map[string]link.Link),
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

	// TCP-SENDPAGE
	if link, err := link.Kprobe("tcp_sendpage", c.objs.KprobeTcpSendpage, nil); err != nil {
		return err
	} else {
		c.links["kprobe/tcp_sendpage"] = link
	}
	if link, err := link.Kretprobe("tcp_sendpage", c.objs.KretprobeTcpSendpage, nil); err != nil {
		return err
	} else {
		c.links["kretprobe/tcp_sendpage"] = link
	}

	// TCP-SENDMSG
	if link, err := link.Kprobe("tcp_sendmsg", c.objs.KprobeTcpSendmsg, nil); err != nil {
		return err
	} else {
		c.links["kprobe/tcp_sendmsg"] = link
	}
	if link, err := link.Kretprobe("tcp_sendmsg", c.objs.KretprobeTcpSendmsg, nil); err != nil {
		return err
	} else {
		c.links["kretprobe/tcp_sendmsg"] = link
	}

	// TCP-RECV
	if link, err := link.Kprobe("tcp_cleanup_rbuf", c.objs.KprobeTcpCleanupRbuf, nil); err != nil {
		return err
	} else {
		c.links["kprobe/tcp_cleanup_rbuf"] = link
	}

	// UDP-SEND-IPv4
	if link, err := link.Kprobe("udp_sendmsg", c.objs.KprobeUdpSendmsg, nil); err != nil {
		return err
	} else {
		c.links["kprobe/udp_sendmsg"] = link
	}
	if link, err := link.Kretprobe("udp_sendmsg", c.objs.KretprobeUdpSendmsg, nil); err != nil {
		return err
	} else {
		c.links["kretprobe/udp_sendmsg"] = link
	}

	// UDP-SEND-IPv6
	if link, err := link.Kprobe("udpv6_sendmsg", c.objs.KprobeUdpv6Sendmsg, nil); err != nil {
		return err
	} else {
		c.links["kprobe/udpv6_sendmsg"] = link
	}
	if link, err := link.Kretprobe("udpv6_sendmsg", c.objs.KretprobeUdpv6Sendmsg, nil); err != nil {
		return err
	} else {
		c.links["kretprobe/udpv6_sendmsg"] = link
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
			c.logger.Error("lookup %d failed: %v", key, err)
		}
	}

	container := "000000000000"
	flows[container] = &flow
	return flows
}
