package types

type FlowData map[uint32]uint64 // key对应C代码中的L4_TCP_SEND_V4等枚举

// FlowMap 全局流量映射 [容器ID] => 流量统计
type FlowMap map[string]*FlowData

// 流量类型枚举（必须与C代码定义的14种类型完全一致）
type FlowType uint32

type FlowCgroup map[uint64]uint64

const (
	L4_TCP_SEND_V4 FlowType = iota
	L4_TCP_RECV_V4
	L4_UDP_SEND_V4
	L4_UDP_RECV_V4
	L3_TCP_SEND_V4
	L3_UDP_SEND_V4
	L3_RAW_SEND_V4
	L4_TCP_SEND_V6
	L4_TCP_RECV_V6
	L4_UDP_SEND_V6
	L4_UDP_RECV_V6
	L3_TCP_SEND_V6
	L3_UDP_SEND_V6
	L3_RAW_SEND_V6
	LN_ALL_TYPES
)

var AllFlowTypes = []FlowType{
	L4_TCP_SEND_V4,
	L4_TCP_RECV_V4,
	L4_UDP_SEND_V4,
	L4_UDP_RECV_V4,
	L3_TCP_SEND_V4,
	L3_UDP_SEND_V4,
	L3_RAW_SEND_V4,
	L4_TCP_SEND_V6,
	L4_TCP_RECV_V6,
	L4_UDP_SEND_V6,
	L4_UDP_RECV_V6,
	L3_TCP_SEND_V6,
	L3_UDP_SEND_V6,
	L3_RAW_SEND_V6,
}

// #define L4_TCP_SEND_V4 0
// #define L4_TCP_RECV_V4 1
// #define L4_UDP_SEND_V4 2
// #define L4_UDP_RECV_V4 3
// #define L3_TCP_SEND_V4 4
// #define L3_UDP_SEND_V4 5
// #define L3_RAW_SEND_V4 6
// #define L4_TCP_SEND_V6 7
// #define L4_TCP_RECV_V6 8
// #define L4_UDP_SEND_V6 9
// #define L4_UDP_RECV_V6 10
// #define L3_TCP_SEND_V6 11
// #define L3_UDP_SEND_V6 12
// #define L3_RAW_SEND_V6 13
