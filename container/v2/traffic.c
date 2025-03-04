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
#define NAME_LEN 14
#define DEVICE_LEN 16

struct netflow_key_t {
    u16 family;
    char container_id[NAME_LEN];
};

struct bpf_map_def SEC("maps") L4_tcp_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};
struct bpf_map_def SEC("maps") L4_tcp_recv_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};

struct bpf_map_def SEC("maps") L4_udp_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};
struct bpf_map_def SEC("maps") L4_udp_recv_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};

struct bpf_map_def SEC("maps") L3_tcp_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};
struct bpf_map_def SEC("maps") L3_udp_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};
struct bpf_map_def SEC("maps") L3_raw_send_bytes = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(struct netflow_key_t),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};

struct bpf_map_def SEC("maps") tcp_sock_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(struct netflow_key_t),
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

static void fill_container_id(char *container_id) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return;
    }

    struct kernfs_node *knode = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn);
    struct kernfs_node *parent = BPF_CORE_READ(knode, parent);
    if (parent) {
        const char *name_ptr = BPF_CORE_READ(knode, name);
        bpf_core_read_str(container_id, NAME_LEN, name_ptr);
    }
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

SEC("fexit/udp_sendmsg")
int BPF_PROG(fexit_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len, int result) {
    if (result <= 0) {
        return 0;
    }

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    int ret = (msg_name) ? msghdr_lo_filter(msg_name) : sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    struct netflow_key_t key = {.family = AF_INET};
    fill_container_id(key.container_id);
    update(&L4_udp_send_bytes, &key, len);

    return 0;
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(fexit_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len, int result) {
    if (result <= 0) {
        return 0;
    }

    void *msg_name = BPF_CORE_READ(msg, msg_name);
    int ret = (msg_name) ? msghdr_lo_filter(msg_name) : sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }

    if (ret == AF_INET6) {
        struct netflow_key_t key = {.family = AF_INET6};
        fill_container_id(key.container_id);
        update(&L4_udp_send_bytes, &key, len);
    }

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
    struct netflow_key_t key = {.family = family};
    fill_container_id(key.container_id);
    update(&L4_udp_recv_bytes, &key, len);

    return 0;
}

static inline int handle_tcp_send(struct sock *sk, int result) {
    int ret = sock_lo_filter(sk);
    if (ret <= 0) {
        return 0;
    }
    u16 family = ret;

    if (result > 0) {
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        update(&L4_tcp_send_bytes, &key, result);
    }

    struct netflow_key_t key = {.family = family};
    fill_container_id(key.container_id);
    bpf_map_update_elem(&tcp_sock_map, &sk, &key, BPF_ANY);

    return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(fexit_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size, int result) {
    return handle_tcp_send(sk, result);
}

SEC("fexit/tcp_sendpage")
int BPF_PROG(fexit_tcp_sendpage, struct sock *sk, struct page *pg, int offset, size_t size,
             int flags, int result) {
    return handle_tcp_send(sk, result);
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
    struct netflow_key_t key = {.family = family};
    fill_container_id(key.container_id);
    update(&L4_tcp_recv_bytes, &key, copied);

    return 0;
}

SEC("kprobe/inet_csk_destroy_sock")
int BPF_KPROBE(kprobe_inet_csk_destroy_sock, struct sock *sk) {
    bpf_map_delete_elem(&tcp_sock_map, &sk);
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
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        update(&L3_udp_send_bytes, &key, length);
    } else if (protocol == IPPROTO_TCP) {
        struct netflow_key_t *key_ptr = bpf_map_lookup_elem(&tcp_sock_map, &sk);
        if (key_ptr != NULL) {
            update(&L3_tcp_send_bytes, key_ptr, length);
        } else {
            struct netflow_key_t key = {.family = family};
            fill_container_id(key.container_id);
            update(&L3_tcp_send_bytes, &key, length);
        }
    } else {
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        update(&L3_raw_send_bytes, &key, length);
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
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        update(&L3_udp_send_bytes, &key, length);
    } else if (protocol == IPPROTO_TCP) {
        struct netflow_key_t *key_ptr = bpf_map_lookup_elem(&tcp_sock_map, &sk);
        if (key_ptr != NULL) {
            update(&L3_tcp_send_bytes, key_ptr, length);
        } else {
            struct netflow_key_t key = {.family = family};
            fill_container_id(key.container_id);
            update(&L3_tcp_send_bytes, &key, length);
        }
    } else {
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        update(&L3_raw_send_bytes, &key, length);
    }

    return 0;
}
