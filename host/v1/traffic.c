// clang-format off
//go:build ignore
#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

char __license[] SEC("license") = "Dual MIT/GPL";

#define IN_IS_ADDR_LOOPBACK(a)                                      \
    (__extension__({                                                \
        const u8 *__a = (const u8 *)&a;                             \
        __a[0] == 127 && __a[1] == 0 && __a[2] == 0 && __a[3] == 1; \
    }))

#define IN6_IS_ADDR_LOOPBACK(a)                                                        \
    (__extension__({                                                                   \
        const struct in6_addr *__a = (const struct in6_addr *)(a);                     \
        __a->in6_u.u6_addr32[0] == 0 && __a->in6_u.u6_addr32[1] == 0 &&                \
            __a->in6_u.u6_addr32[2] == 0 && __a->in6_u.u6_addr32[3] == __bpf_htonl(1); \
    }))

#define IN6_IS_ADDR_V4MAPPED_LOOPBACK(a)                                \
    (__extension__({                                                    \
        const struct in6_addr *__a = (const struct in6_addr *)(a);      \
        __a->in6_u.u6_addr32[0] == 0 && __a->in6_u.u6_addr32[1] == 0 && \
            __a->in6_u.u6_addr32[2] == __bpf_htonl(0xffff) &&           \
            __a->in6_u.u6_addr32[3] == __bpf_htonl(0x7f000001);         \
    }))

#define IN6_IS_ADDR_V4MAPPED(a)                                         \
    (__extension__({                                                    \
        const struct in6_addr *__a = (const struct in6_addr *)(a);      \
        __a->in6_u.u6_addr32[0] == 0 && __a->in6_u.u6_addr32[1] == 0 && \
            __a->in6_u.u6_addr32[2] == __bpf_htonl(0xffff);             \
    }))

#define IN6_IS_CONN_LOCAL(s, d)                                    \
    (__extension__({                                               \
        const struct in6_addr *__s = (const struct in6_addr *)(s); \
        const struct in6_addr *__d = (const struct in6_addr *)(d); \
        __s->in6_u.u6_addr32[0] == __d->in6_u.u6_addr32[0] &&      \
            __s->in6_u.u6_addr32[1] == __d->in6_u.u6_addr32[1] &&  \
            __s->in6_u.u6_addr32[2] == __d->in6_u.u6_addr32[2] &&  \
            __s->in6_u.u6_addr32[3] == __d->in6_u.u6_addr32[3];    \
    }))

#define AF_INET  2
#define AF_INET6 10
#define DEVICE_LEN 16

#define L4_TCP_SEND_V4 0
#define L4_TCP_RECV_V4 1
#define L4_UDP_SEND_V4 2
#define L4_UDP_RECV_V4 3
#define L3_TCP_SEND_V4 4
#define L3_UDP_SEND_V4 5
#define L3_RAW_SEND_V4 6
#define L4_TCP_SEND_V6 7
#define L4_TCP_RECV_V6 8
#define L4_UDP_SEND_V6 9
#define L4_UDP_RECV_V6 10
#define L3_TCP_SEND_V6 11
#define L3_UDP_SEND_V6 12
#define L3_RAW_SEND_V6 13

struct bpf_map_def SEC("maps") network_flow_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 14,
};

struct bpf_map_def SEC("maps") tcp_sendmsg_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),   // pid
    .value_size = sizeof(u16), // family
    .max_entries = 10240,
};
struct bpf_map_def SEC("maps") udp_sendmsg_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),   // pid
    .value_size = sizeof(u16), // family
    .max_entries = 10240,
};

static inline void update(void *map, const void *key, u64 value) {
    u64 *value_ptr = bpf_map_lookup_elem(map, key);
    if (value_ptr != 0) {
        *value_ptr += value;
    } else {
        bpf_map_update_elem(map, key, &value, BPF_ANY);
    }
}

static inline int check_veth(struct sk_buff *skb) {
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        char name[DEVICE_LEN];
        bpf_probe_read_str(name, DEVICE_LEN, (const void *)dev->name);

        if (name[0] == 'd' &&
            name[1] == 'o' &&
            name[2] == 'c' &&
            name[3] == 'k' &&
            name[4] == 'e' &&
            name[5] == 'r' &&
            name[6] == '0') {
            return 1;
        }
    }
    return 0;
}

static int sock_lo_filter(struct sock *sk) {
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        u32 sa = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        u32 da = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        if (IN_IS_ADDR_LOOPBACK(sa)) return -1;
        if (IN_IS_ADDR_LOOPBACK(da)) return -1;
        if (sa == da) return -1;

        return AF_INET;
    }

    if (family == AF_INET6) {
        struct in6_addr sa = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr da = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);

        if (IN6_IS_ADDR_LOOPBACK(&da)) return -1;
        if (IN6_IS_ADDR_LOOPBACK(&sa)) return -1;
        if (IN6_IS_CONN_LOCAL(&sa, &da)) return -1;

        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&da)) return -1;
        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&sa)) return -1;
        if (IN6_IS_ADDR_V4MAPPED(&da)) return AF_INET;
        if (IN6_IS_ADDR_V4MAPPED(&sa)) return AF_INET;

        return AF_INET6;
    }

    return 0;
}

static int msghdr_lo_filter(void *msg_name) {
    struct sockaddr *sa = (struct sockaddr *)msg_name;
    u16 family = BPF_CORE_READ(sa, sa_family);

    if (family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)msg_name;
        struct in6_addr addr = BPF_CORE_READ(in6, sin6_addr);
        if (IN6_IS_ADDR_LOOPBACK(&addr)) return -1;
        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&addr)) return -1;
        if (IN6_IS_ADDR_V4MAPPED(&addr)) return AF_INET;
        return AF_INET6;
    }

    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)msg_name;
        u32 addr = BPF_CORE_READ(in, sin_addr.s_addr);
        if (IN_IS_ADDR_LOOPBACK(addr)) return -1;
        return AF_INET;
    }

    return 0;
}

static int skb_lo_filter(struct sk_buff *skb) {
    char *head = (char *)BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    char *iphdr_ptr = head + network_header;

    // IP头部的第一个字节包含了版本信息和头部长度:
    u8 ihl = 0; // IHL (Internet Header Length)
    bpf_core_read(&ihl, sizeof(ihl), iphdr_ptr);
    u8 ip_version = ihl >> 4; // IP版本位于该字节的最高四位。

    if (ip_version == 4) {
        struct iphdr *iphdr = (struct iphdr *)iphdr_ptr;
        u32 saddr = BPF_CORE_READ(iphdr, saddr);
        u32 daddr = BPF_CORE_READ(iphdr, daddr);

        if (IN_IS_ADDR_LOOPBACK(saddr)) return -1;
        if (IN_IS_ADDR_LOOPBACK(daddr)) return -1;
        if (saddr == daddr) return -1;

        return AF_INET;
    }

    if (ip_version == 6) {
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)iphdr_ptr;
        struct in6_addr saddr = BPF_CORE_READ(ipv6hdr, saddr);
        struct in6_addr daddr = BPF_CORE_READ(ipv6hdr, daddr);

        if (IN6_IS_ADDR_LOOPBACK(&saddr)) return -1;
        if (IN6_IS_ADDR_LOOPBACK(&daddr)) return -1;
        if (IN6_IS_CONN_LOCAL(&saddr, &daddr)) return -1;

        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&saddr)) return -1;
        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&daddr)) return -1;
        if (IN6_IS_ADDR_V4MAPPED(&saddr)) return AF_INET;
        if (IN6_IS_ADDR_V4MAPPED(&daddr)) return AF_INET;

        return AF_INET6;
    }

    return -1;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    void *msg_name = BPF_CORE_READ(msg, msg_name); // 区分是有是有连接的udp流量
    int ret = (msg_name) ? msghdr_lo_filter(msg_name) : sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    u16 family = ret;
    u32 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_sendmsg_map, &pid, &family, BPF_ANY);

    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(kretprobe_udp_sendmsg) {
    int ret = PT_REGS_RC(ctx);

    u32 pid = bpf_get_current_pid_tgid();
    u16 *family = bpf_map_lookup_elem(&udp_sendmsg_map, &pid);
    if (family == NULL) {
        return 0;
    }

    if (ret > 0) {
        u32 key = (*family == AF_INET) ? L4_UDP_SEND_V4 : L4_UDP_SEND_V6;
        update(&network_flow_map, &key, ret);
    }

    bpf_map_delete_elem(&udp_sendmsg_map, &pid);

    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    void *msg_name = BPF_CORE_READ_USER(msg, msg_name);
    int ret = (msg_name) ? msghdr_lo_filter(msg_name) : sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    u16 family = ret;
    u32 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_sendmsg_map, &pid, &family, BPF_ANY);

    return 0;
}

SEC("kretprobe/udpv6_sendmsg")
int BPF_KRETPROBE(kretprobe_udpv6_sendmsg) {
    u32 pid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);

    u16 *family = bpf_map_lookup_elem(&udp_sendmsg_map, &pid);
    if (family == 0) {
        return 0;
    }

    if (ret > 0) {
        u32 key = (*family == AF_INET) ? L4_UDP_SEND_V4 : L4_UDP_SEND_V6;
        update(&network_flow_map, &key, ret);
    }

    bpf_map_delete_elem(&udp_sendmsg_map, &pid);

    return 0;
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
    if (len <= 0) {
        return 0;
    }

    int ret = skb_lo_filter(skb);
    if (ret < 0) {
        return 0;
    }

    u16 family = ret;
    u32 key = (family == AF_INET) ? L4_UDP_RECV_V4 : L4_UDP_RECV_V6;
    update(&network_flow_map, &key, len);

    return 0;
}

static inline int handle_tcp_send(struct sock *sk) {
    int ret = sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    u16 family = ret;
    u32 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_sendmsg_map, &pid, &family, BPF_ANY);

    return 0;
}

static inline int handle_tcp_send_ret(int result) {
    u32 pid = bpf_get_current_pid_tgid();
    u16 *family = bpf_map_lookup_elem(&tcp_sendmsg_map, &pid);
    if (family == NULL) {
        return 0;
    }

    if (result > 0) {
        u32 key = (*family == AF_INET) ? L4_TCP_SEND_V4 : L4_TCP_SEND_V6;
        update(&network_flow_map, &key, result);
    }

    bpf_map_delete_elem(&tcp_sendmsg_map, &pid);

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return handle_tcp_send(sk);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg) {
    return handle_tcp_send_ret(PT_REGS_RC(ctx));
}

SEC("kprobe/tcp_sendpage")
int BPF_KPROBE(kprobe_tcp_sendpage, struct sock *sk, struct page *pg, int offset, size_t size,int flags) {
    return handle_tcp_send(sk);
}

SEC("kretprobe/tcp_sendpage")
int BPF_KRETPROBE(kretprobe_tcp_sendpage) {
    return handle_tcp_send_ret(PT_REGS_RC(ctx));
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0) {
        return 0;
    }

    int ret = sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    u16 family = ret;
    u32 key = (family == AF_INET) ? L4_TCP_RECV_V4 : L4_TCP_RECV_V6;
    update(&network_flow_map, &key, copied);

    return 0;
}

SEC("kprobe/ip_output")
int BPF_KPROBE(kprobe_ip_output, struct net *net, struct sock *sk, struct sk_buff *skb) {
    if (check_veth(skb)) {
        return 0;
    }
    char *head = (char *)BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    struct iphdr *iphdr = (struct iphdr *)(head + network_header);

    u16 family = AF_INET;
    u32 saddr = BPF_CORE_READ(iphdr, saddr);
    u32 daddr = BPF_CORE_READ(iphdr, daddr);
    if (IN_IS_ADDR_LOOPBACK(saddr)) return 0;
    if (IN_IS_ADDR_LOOPBACK(daddr)) return 0;
    if (saddr == daddr) return 0;

    u32 length = BPF_CORE_READ(skb, len);
    u8 protocol = BPF_CORE_READ(iphdr, protocol);
    if (protocol == IPPROTO_UDP) {
        u32 key = (family == AF_INET) ? L3_UDP_SEND_V4 : L3_UDP_SEND_V6;
        update(&network_flow_map, &key, length);
    } else if (protocol == IPPROTO_TCP) {
        u32 key = (family == AF_INET) ? L3_TCP_SEND_V4 : L3_TCP_SEND_V6;
        update(&network_flow_map, &key, length);
    } else {
        u32 key = (family == AF_INET) ? L3_RAW_SEND_V4 : L3_RAW_SEND_V6;
        update(&network_flow_map, &key, length);
    }

    return 0;
}

SEC("kprobe/ip6_output")
int BPF_KPROBE(kprobe_ip6_output, struct net *net, struct sock *sk, struct sk_buff *skb) {
    char *head = (char *)BPF_CORE_READ(skb, head);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    struct ipv6hdr *iphdr = (struct ipv6hdr *)(head + network_header);

    u16 family = AF_INET6;
    struct in6_addr saddr = BPF_CORE_READ(iphdr, saddr);
    struct in6_addr daddr = BPF_CORE_READ(iphdr, daddr);
    if (IN6_IS_ADDR_LOOPBACK(&saddr)) return 0;
    if (IN6_IS_ADDR_LOOPBACK(&daddr)) return 0;
    if (IN6_IS_CONN_LOCAL(&saddr, &daddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&saddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&daddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED(&saddr)) family = AF_INET;
    if (IN6_IS_ADDR_V4MAPPED(&daddr)) family = AF_INET;

    u32 length = BPF_CORE_READ(skb, len);
    u8 protocol = BPF_CORE_READ(iphdr, nexthdr);
    if (protocol == IPPROTO_UDP) {
        u32 key = (family == AF_INET) ? L3_UDP_SEND_V4 : L3_UDP_SEND_V6;
        update(&network_flow_map, &key, length);
    } else if (protocol == IPPROTO_TCP) {
        u32 key = (family == AF_INET) ? L3_TCP_SEND_V4 : L3_TCP_SEND_V6;
        update(&network_flow_map, &key, length);
    } else {
        u32 key = (family == AF_INET) ? L3_RAW_SEND_V4 : L3_RAW_SEND_V6;
        update(&network_flow_map, &key, length);
    }

    return 0;
}
