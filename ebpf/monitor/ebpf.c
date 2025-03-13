// clang-format off
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#define TC_ACT_OK 1

char __license[] SEC("license") = "Dual MIT/GPL";



struct bpf_map_def SEC("maps") ingress_stats = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") egress_stats = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 1024,
};

SEC("cgroup_skb/ingress")
int cgroup_ingress(struct __sk_buff *skb) {
    u64 cgroup_id = bpf_skb_cgroup_id(skb);
    u64 *value = bpf_map_lookup_elem(&ingress_stats, &cgroup_id);
    u64 bytes = skb->len;

    if (value) {
        *value += bytes;  
    } else {
        u64 init_val = bytes;
        bpf_map_update_elem(&ingress_stats, &cgroup_id, &init_val, BPF_NOEXIST);
    }
    return TC_ACT_OK;
}

SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb) {
    u64 cgroup_id = bpf_skb_cgroup_id(skb);
    u64 *value = bpf_map_lookup_elem(&egress_stats, &cgroup_id);
    u64 bytes = skb->len;

    if (value) {
        *value += bytes;  
    } else {
        u64 init_val = bytes;
        bpf_map_update_elem(&egress_stats, &cgroup_id, &init_val, BPF_NOEXIST);
    }
    return TC_ACT_OK;
}
