// clang-format off
//go:build ignore
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/inet_sock.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ipv6.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/netdevice.h> // 包含 net_device 结构体定义的头文件
#include <linux/if_ether.h> // 包含 DEVICE_LEN 的定义
// clang-format on

#define member_address(source_struct, source_member)                                             \
    ({                                                                                           \
        void *__ret;                                                                             \
        __ret =                                                                                  \
            (void *)(((char *)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                                                   \
    })
#define member_read(destination, source_struct, source_member)            \
    do {                                                                  \
        bpf_probe_read(destination, sizeof(source_struct->source_member), \
                       member_address(source_struct, source_member));     \
    } while (0)

#define IN6_IS_ADDR_LOOPBACK(a)                                                       \
    (__extension__({                                                                  \
        const struct in6_addr *__a = (const struct in6_addr *)(a);                    \
        __a->s6_addr32[0] == 0 && __a->s6_addr32[1] == 0 && __a->s6_addr32[2] == 0 && \
            __a->s6_addr32[3] == htonl(1);                                            \
    }))

#define IN6_IS_ADDR_V4MAPPED_LOOPBACK(a)                                                          \
    (__extension__({                                                                              \
        const struct in6_addr *__a = (const struct in6_addr *)(a);                                \
        __a->s6_addr32[0] == 0 && __a->s6_addr32[1] == 0 && __a->s6_addr32[2] == htonl(0xffff) && \
            __a->s6_addr32[3] == htonl(0x7f000001);                                               \
    }))

#define IN6_IS_ADDR_V4MAPPED(a)                                                                 \
    (__extension__({                                                                            \
        const struct in6_addr *__a = (const struct in6_addr *)(a);                              \
        __a->s6_addr32[0] == 0 && __a->s6_addr32[1] == 0 && __a->s6_addr32[2] == htonl(0xffff); \
    }))

#define IN6_IS_CONN_LOCAL(source, dest)                                                       \
    (__extension__({                                                                          \
        const struct in6_addr *__s = (const struct in6_addr *)(source);                       \
        const struct in6_addr *__d = (const struct in6_addr *)(dest);                         \
        __s->s6_addr32[0] == __d->s6_addr32[0] && __s->s6_addr32[1] == __d->s6_addr32[1] &&   \
            __s->s6_addr32[2] == __d->s6_addr32[2] && __s->s6_addr32[3] == __d->s6_addr32[3]; \
    }))

#define NAME_LEN 14
#define DEVICE_LEN 16

struct netflow_key_t {
    u16 family;
    char container_id[NAME_LEN];
};

BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L4_tcp_send_bytes, 10240);
BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L4_tcp_recv_bytes, 10240);
BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L4_udp_send_bytes, 10240);
BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L4_udp_recv_bytes, 10240);

BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L3_tcp_send_bytes, 10240);
BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L3_udp_send_bytes, 10240);
BPF_TABLE("lru_percpu_hash", struct netflow_key_t, u64, L3_raw_send_bytes, 10240);

BPF_TABLE("lru_hash", struct sock *, struct netflow_key_t, tcpsock, 102400);
BPF_TABLE("lru_hash", u32, u16, tcp_sendmsg_in, 102400);
BPF_TABLE("lru_hash", u32, u16, udp_sendmsg_in, 102400);

static void fill_container_id(char *container_id) {
    struct task_struct *curr_task;
    struct css_set *css;
    struct cgroup_subsys_state *sbs;
    struct cgroup *cg;
    struct kernfs_node *knode, *pknode;
    char *name;
    int name_shift = 0;

    curr_task = (struct task_struct *)bpf_get_current_task();
    css = curr_task->cgroups;
    bpf_probe_read(&sbs, sizeof(void *), &css->subsys[0]);
    bpf_probe_read(&cg, sizeof(void *), &sbs->cgroup);

    // Reading fspath
    bpf_probe_read(&knode, sizeof(void *), &cg->kn);
    bpf_probe_read(&pknode, sizeof(void *), &knode->parent);

    if (pknode != NULL) {
        char *aus;
        bpf_probe_read(&aus, sizeof(void *), &knode->name);
        bpf_probe_read_str(container_id, 12 + 1, aus);
    }
}

static int check_veth(struct sk_buff *skb) {
    struct net_device *dev_ptr;
    bpf_probe_read(&dev_ptr, sizeof(void *), &skb->dev);
    if (dev_ptr != NULL) {
        char* name_ptr;
        bpf_probe_read(&name_ptr, sizeof(void *), &dev_ptr->name);
        char* name;
        bpf_probe_read_str(name, DEVICE_LEN + 1, name_ptr);
        
        if (strncmp(name, "docker0", 7) == 0) {
            return 1;
        }
    }
    return 0;
}

static int sock_lo_filter(struct sock *sk) {
    unsigned char *sp, *dp;
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 family = inet->sk.__sk_common.skc_family;
    // filter ipv4
    if (family == AF_INET) {
        sp = (unsigned char *)&(inet->inet_saddr);
        if (sp[0] == 127 && sp[1] == 0 && sp[2] == 0 && sp[3] == 1) return -1;
        dp = (unsigned char *)&(inet->inet_daddr);
        if (dp[0] == 127 && dp[1] == 0 && dp[2] == 0 && dp[3] == 1) return -1;

        if (sp[0] == dp[0] && sp[1] == dp[1] && sp[2] == dp[2] && sp[3] == dp[3]) return -1;

        return 0;
    }
    // filter ipv6
    if (family == AF_INET6) {
        struct in6_addr daddr, saddr;
        daddr = inet->sk.__sk_common.skc_v6_daddr;
        saddr = inet->sk.__sk_common.skc_v6_rcv_saddr;
        if (IN6_IS_ADDR_LOOPBACK(&daddr) || IN6_IS_ADDR_LOOPBACK(&saddr)) return -1;

        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&daddr) || IN6_IS_ADDR_V4MAPPED_LOOPBACK(&saddr))
            return -1;

        if (IN6_IS_CONN_LOCAL(&saddr, &daddr)) return -1;

        if (IN6_IS_ADDR_V4MAPPED(&daddr)) return AF_INET;
        return 0;
    };

    // non ipv6 or ipv4 package
    return -1;
}

static int msghdr_lo_filter(struct msghdr *msg) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg->msg_name;
    if (sin6) {
        if (sin6->sin6_family == AF_INET6) {
            struct in6_addr daddr, saddr;
            bpf_probe_read_kernel(&daddr, sizeof(daddr), &sin6->sin6_addr);
            if (IN6_IS_ADDR_LOOPBACK(&daddr) || IN6_IS_ADDR_V4MAPPED_LOOPBACK(&daddr)) {
                return -1;
            }
            if (IN6_IS_ADDR_V4MAPPED(&daddr)) {
                return AF_INET;
            }
        } else if (sin6->sin6_family == AF_INET) {
            struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
            if (usin) {
                unsigned char *p;
                p = (unsigned char *)&usin->sin_addr.s_addr;
                if (p[0] == 127 && p[1] == 0 && p[2] == 0 && p[3] == 1) return -1;
            }
        }
    }
    return 0;
}

static int skb_lo_filter(struct sk_buff *skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char *head;
    u16 network_header;
    char *ip_header_address;
    unsigned char *sp, *dp;

    member_read(&head, skb, head);
    member_read(&network_header, skb, network_header);

    // Compute IP Header address
    ip_header_address = head + network_header;

    struct {
        u8 : 4;
        u8 version : 4;
    } ip_version;
    bpf_probe_read(&ip_version, sizeof(ip_version), ip_header_address);

    // filter out 127.0.0.1
    if (ip_version.version == 4) {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        sp = (unsigned char *)&(iphdr.saddr);
        if (sp[0] == 127 && sp[1] == 0 && sp[2] == 0 && sp[3] == 1) return 0;
        dp = (unsigned char *)&(iphdr.daddr);
        if (dp[0] == 127 && dp[1] == 0 && dp[2] == 0 && dp[3] == 1) return 0;
        if (sp[0] == dp[0] && sp[1] == dp[1] && sp[2] == dp[2] && sp[3] == dp[3]) return 0;

        return 0;
    }

    // filter out ::1/128
    if (ip_version.version == 6) {
        struct ipv6hdr ipv6hdr;
        bpf_probe_read(&ipv6hdr, sizeof(ipv6hdr), ip_header_address);

        if (IN6_IS_ADDR_LOOPBACK(&ipv6hdr.saddr) || IN6_IS_ADDR_LOOPBACK(&ipv6hdr.daddr)) return -1;

        if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&ipv6hdr.saddr) ||
            IN6_IS_ADDR_V4MAPPED_LOOPBACK(&ipv6hdr.daddr))
            return -1;

        if (IN6_IS_CONN_LOCAL(&ipv6hdr.saddr, &ipv6hdr.daddr)) return -1;

        if (IN6_IS_ADDR_V4MAPPED(&ipv6hdr.saddr) || IN6_IS_ADDR_V4MAPPED(&ipv6hdr.daddr))
            return AF_INET;

        return 0;
    }

    // non ipv4/ipv6 package
    return -1;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
    u16 family = usin->sin_family;

    if (msghdr_lo_filter(msg)) return 0;

    if (family == AF_INET || family == AF_INET6) {
        u32 tid = bpf_get_current_pid_tgid();
        udp_sendmsg_in.update(&tid, &family);
    }
    // else drop

    return 0;
}

int kprobe__udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg->msg_name;
    u16 family = sin6->sin6_family;

    int ret = msghdr_lo_filter(msg);
    if (ret == AF_INET) {
        family == AF_INET;
    } else if (ret) {
        return 0;
    }

    if (family == AF_INET || family == AF_INET6) {
        u32 tid = bpf_get_current_pid_tgid();
        udp_sendmsg_in.update(&tid, &family);
    }
    // else drop

    return 0;
}

int kretprobe__udp_sendmsg(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);

    u16 *family = udp_sendmsg_in.lookup(&tid);
    if (family == 0) {
        return 0; // missed entry
    }

    if (ret > 0) {
        struct netflow_key_t netflow_key = {.family = *family};
        fill_container_id(netflow_key.container_id);
        u64 *len_ptr = L4_udp_send_bytes.lookup(&netflow_key);
        if (len_ptr != 0) {
            *len_ptr += ret;
        } else {
            u64 len = ret;
            L4_udp_send_bytes.update(&netflow_key, &len);
        }
    }
    udp_sendmsg_in.delete(&tid);
    return 0;
}

int kretprobe__udpv6_sendmsg(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);

    u16 *family = udp_sendmsg_in.lookup(&tid);
    if (family == 0) {
        return 0; // missed entry
    }

    if (ret > 0) {
        struct netflow_key_t netflow_key = {.family = *family};
        fill_container_id(netflow_key.container_id);
        u64 *len_ptr = L4_udp_send_bytes.lookup(&netflow_key);
        if (len_ptr != 0) {
            *len_ptr += ret;
        } else {
            u64 len = ret;
            L4_udp_send_bytes.update(&netflow_key, &len);
        }
    }
    udp_sendmsg_in.delete(&tid);
    return 0;
}

int kprobe__skb_consume_udp(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int len) {
    u64 len64 = len;
    u16 family = sk->__sk_common.skc_family;

    if (len <= 0) return 0;

    int ret = skb_lo_filter(skb);
    if (ret == AF_INET) {
        family = AF_INET;
    } else if (ret) {
        return 0;
    }

    if (family == AF_INET || family == AF_INET6) {
        struct netflow_key_t netflow_key = {.family = family};
        fill_container_id(netflow_key.container_id);
        u64 *len_ptr = L4_udp_recv_bytes.lookup(&netflow_key);
        if (len_ptr != 0) {
            *len_ptr += len64;
        } else {
            L4_udp_recv_bytes.update(&netflow_key, &len64);
        }
    }
    // else drop

    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u16 family = sk->__sk_common.skc_family;

    int ret = sock_lo_filter(sk);
    if (ret == AF_INET) {
        family = AF_INET;
    } else if (ret) {
        return 0;
    }

    if (family == AF_INET || family == AF_INET6) {
        u32 tid = bpf_get_current_pid_tgid();
        struct netflow_key_t netflow_key = {.family = family};
        fill_container_id(netflow_key.container_id);

        tcp_sendmsg_in.update(&tid, &family);
        tcpsock.update(&sk, &netflow_key);
    }
    // else drop

    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    int ret = PT_REGS_RC(ctx);

    u16 *family = tcp_sendmsg_in.lookup(&tid);
    if (family == NULL) {
        return 0;
    }

    if (ret > 0) {
        struct netflow_key_t key = {.family = *family};
        fill_container_id(key.container_id);
        u64 *len_ptr = L4_tcp_send_bytes.lookup(&key);
        if (len_ptr != 0) {
            *len_ptr += ret;
        } else {
            u64 len = ret;
            L4_tcp_send_bytes.update(&key, &len);
        }
    }
    tcp_sendmsg_in.delete(&tid);
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    u64 len = copied;
    u16 family = sk->__sk_common.skc_family;

    if (copied <= 0) return 0;

    int ret = sock_lo_filter(sk);
    if (ret == AF_INET) {
        family = AF_INET;
    } else if (ret) {
        return 0;
    }

    if (family == AF_INET || family == AF_INET6) {
        struct netflow_key_t key = {.family = family};
        fill_container_id(key.container_id);
        u64 *len_ptr = L4_tcp_recv_bytes.lookup(&key);
        if (len_ptr != 0) {
            *len_ptr += len;
        } else {
            L4_tcp_recv_bytes.update(&key, &len);
        }
        tcpsock.update(&sk, &key);
    }

    return 0;
}

int kprobe__inet_csk_destroy_sock(struct pt_regs *ctx, struct sock *sk) {
    tcpsock.delete(&sk);
    return 0;
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    if (check_veth(skb)) {
        return 0;
    }
    char *head;
    u16 network_header;
    struct iphdr iphdr;
    member_read(&head, skb, head);
    member_read(&network_header, skb, network_header);
    bpf_probe_read(&iphdr, sizeof(iphdr), head + network_header);

    // filter out 127.0.0.1
    unsigned char *sp = (unsigned char *)&(iphdr.saddr);
    unsigned char *dp = (unsigned char *)&(iphdr.daddr);
    if (sp[0] == 127 && sp[1] == 0 && sp[2] == 0 && sp[3] == 1) return 0;
    if (dp[0] == 127 && dp[1] == 0 && dp[2] == 0 && dp[3] == 1) return 0;
    if (sp[0] == dp[0] && sp[1] == dp[1] && sp[2] == dp[2] && sp[3] == dp[3]) return 0;

    u64 len = skb->len;
    u8 proto = iphdr.protocol;
    if (proto == IPPROTO_UDP) {
        struct netflow_key_t key = {.family = AF_INET};
        fill_container_id(key.container_id);
        u64 *len_ptr = L3_udp_send_bytes.lookup(&key);
        if (len_ptr != NULL) {
            *len_ptr += len;
        } else {
            L3_udp_send_bytes.update(&key, &len);
        }
    } else if (proto == IPPROTO_TCP) {
        struct netflow_key_t *key_ptr = tcpsock.lookup(&sk);
        if (key_ptr != NULL) {
            u64 *len_ptr = L3_tcp_send_bytes.lookup(key_ptr);
            if (len_ptr != 0) {
                *len_ptr += len;
            } else {
                L3_tcp_send_bytes.update(key_ptr, &len);
            }
        } else {
            struct netflow_key_t key = {.family = AF_INET};
            fill_container_id(key.container_id);
            u64 *len_ptr = L3_tcp_send_bytes.lookup(&key);
            if (len_ptr != NULL) {
                *len_ptr += len;
            } else {
                L3_tcp_send_bytes.update(&key, &len);
            }
        }
    } else {
        struct netflow_key_t key = {.family = AF_INET};
        fill_container_id(key.container_id);
        u64 *len_ptr = L3_raw_send_bytes.lookup(&key);
        if (len_ptr != NULL) {
            *len_ptr += len;
        } else {
            L3_raw_send_bytes.update(&key, &len);
        }
    }
    return 0;
}

int kprobe__ip6_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    char *head;
    u16 network_header;
    u8 l4proto;
    char *ip_header_address;
    u64 len = skb->len;
    unsigned char *p;
    u16 family = AF_INET6;

    member_read(&head, skb, head);
    member_read(&network_header, skb, network_header);

    // Compute IP Header address
    ip_header_address = head + network_header;
    struct ipv6hdr ipv6hdr;
    bpf_probe_read(&ipv6hdr, sizeof(ipv6hdr), ip_header_address);

    // filter out ::1/128
    if (IN6_IS_ADDR_LOOPBACK(&ipv6hdr.saddr)) return 0;
    if (IN6_IS_ADDR_LOOPBACK(&ipv6hdr.daddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&ipv6hdr.saddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED_LOOPBACK(&ipv6hdr.daddr)) return 0;
    if (IN6_IS_CONN_LOCAL(&ipv6hdr.saddr, &ipv6hdr.daddr)) return 0;
    if (IN6_IS_ADDR_V4MAPPED(&ipv6hdr.saddr)) family = AF_INET;
    if (IN6_IS_ADDR_V4MAPPED(&ipv6hdr.daddr)) family = AF_INET;

    l4proto = ipv6hdr.nexthdr; // udp/tcp proto

    struct netflow_key_t netflow_key = {.family = family};
    if (l4proto == IPPROTO_UDP) {
        fill_container_id(netflow_key.container_id);
        u64 *len_ptr = L3_udp_send_bytes.lookup(&netflow_key);
        if (len_ptr != 0) {
            *len_ptr += len;
        } else {
            L3_udp_send_bytes.update(&netflow_key, &len);
        }
    } else if (l4proto == IPPROTO_TCP) {
        struct netflow_key_t *netflow_key_ptr = tcpsock.lookup(&sk);
        if (netflow_key_ptr != 0) {
            u64 *len_ptr = L3_tcp_send_bytes.lookup(netflow_key_ptr);
            if (len_ptr != 0) {
                *len_ptr += len;
            } else {
                L3_tcp_send_bytes.update(netflow_key_ptr, &len);
            }
        } else {
            fill_container_id(netflow_key.container_id);
            u64 *len_ptr = L3_tcp_send_bytes.lookup(&netflow_key);
            if (len_ptr != 0) {
                *len_ptr += len;
            } else {
                L3_tcp_send_bytes.update(&netflow_key, &len);
            }
        }
    } else {
        fill_container_id(netflow_key.container_id);
        u64 *len_ptr = L3_raw_send_bytes.lookup(&netflow_key);
        if (len_ptr != 0) {
            *len_ptr += len;
        } else {
            L3_raw_send_bytes.update(&netflow_key, &len);
        }
    }
    return 0;
}
