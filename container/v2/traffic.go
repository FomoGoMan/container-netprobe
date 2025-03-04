package traffic

import (
	"encoding/binary"
	"go_minion/internal/collector/types"
	"go_minion/pkg/logger"
	"go_minion/pkg/utility"

	"github.com/cilium/ebpf"
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
		logger: logger.NewFieldLogger(fileLogger, "ebpf-container-v2"),
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

	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitTcpSendpage}); err != nil {
		return err
	} else {
		c.links["fexit/tcp_sendpage"] = link
	}

	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitTcpSendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/tcp_sendmsg"] = link
	}

	if link, err := link.Kprobe("tcp_cleanup_rbuf", c.objs.KprobeTcpCleanupRbuf, nil); err != nil {
		return err
	} else {
		c.links["kprobe/tcp_cleanup_rbuf"] = link
	}

	if link, err := link.Kprobe("inet_csk_destroy_sock", c.objs.KprobeInetCskDestroySock, nil); err != nil {
		return err
	} else {
		c.links["kprobe/inet_csk_destroy_sock"] = link
	}

	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitUdpSendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/udp_sendmsg"] = link
	}

	if link, err := link.AttachTracing(link.TracingOptions{Program: c.objs.FexitUdpv6Sendmsg}); err != nil {
		return err
	} else {
		c.links["fexit/udpv6_sendmsg"] = link
	}

	if link, err := link.Kprobe("skb_consume_udp", c.objs.KprobeSkbConsumeUdp, nil); err != nil {
		return err
	} else {
		c.links["kprobe/skb_consume_udp"] = link
	}

	if link, err := link.Kprobe("ip_output", c.objs.KprobeIpOutput, nil); err != nil {
		return err
	} else {
		c.links["kprobe/ip_output"] = link
	}

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

func (c *Collector) CollectFlows(flows types.FlowMap, name string, m *ebpf.Map, v4Index int, v6Index int) {
	cpus := utility.GetNumOfPossibleCpus()
	key := make([]byte, 16)
	values := make([]uint64, cpus)
	for i := m.Iterate(); i.Next(&key, &values); {
		family := binary.LittleEndian.Uint16(key[0:2])
		container := string(key[2:14])
		bytes := utility.Sum(values)

		// 将空容器ID转为可打印字符
		if container == "\000\000\000\000\000\000\000\000\000\000\000\000" {
			container = "000000000000"
		}

		switch family {
		case types.AF_INET:
			c.logger.Debug("name=%s proto=IPv4 container=%s bytes=%d", name, container, bytes)
			v, ok := flows[container]
			if ok {
				v[v4Index] += bytes
			} else {
				v = &types.FlowData{}
				v[v4Index] = bytes
				flows[container] = v
			}
		case types.AF_INET6:
			c.logger.Debug("name=%s proto=IPv6 container=%s bytes=%d", name, container, bytes)
			v, ok := flows[container]
			if ok {
				v[v6Index] += bytes
			} else {
				v = &types.FlowData{}
				v[v6Index] = bytes
				flows[container] = v
			}
		}
	}
}

func (c *Collector) Collect() types.FlowMap {
	flows := make(map[string]*types.FlowData)
	c.CollectFlows(flows, "L4TcpSend", c.objs.L4TcpSendBytes, int(types.L4TcpSendV4), int(types.L4TcpSendV6))
	c.CollectFlows(flows, "L4TcpRecv", c.objs.L4TcpRecvBytes, int(types.L4TcpRecvV4), int(types.L4TcpRecvV6))
	c.CollectFlows(flows, "L4UdpSend", c.objs.L4UdpSendBytes, int(types.L4UdpSendV4), int(types.L4UdpSendV6))
	c.CollectFlows(flows, "L4UdpRecv", c.objs.L4UdpRecvBytes, int(types.L4UdpRecvV4), int(types.L4UdpRecvV6))
	c.CollectFlows(flows, "L3TcpSend", c.objs.L3TcpSendBytes, int(types.L3TcpSendV4), int(types.L3TcpSendV6))
	c.CollectFlows(flows, "L3UdpSend", c.objs.L3UdpSendBytes, int(types.L3UdpSendV4), int(types.L3UdpSendV6))
	c.CollectFlows(flows, "L3RawSend", c.objs.L3RawSendBytes, int(types.L3RawSendV4), int(types.L3RawSendV6))
	return flows
}
