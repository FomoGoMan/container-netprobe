// clang-format off
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#define TC_ACT_OK 0

char _license[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);   // cgroup_id
    __type(value, u64); // bytes count
    __uint(max_entries, 1024);
} cgroup_stats SEC(".maps");

SEC("cgroup_skb/ingress")
int cgroup_ingress(struct __sk_buff *skb) {
    u64 cgroup_id = bpf_skb_cgroup_id(skb);
    u64 *value = bpf_map_lookup_elem(&cgroup_stats, &cgroup_id);
    u64 bytes = skb->len;

    if (value) {
        __sync_fetch_and_add(value, bytes);
    } else {
        u64 init_val = bytes;
        bpf_map_update_elem(&cgroup_stats, &cgroup_id, &init_val, BPF_NOEXIST);
    }
    return TC_ACT_OK;
}

SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb) {
    u64 cgroup_id = bpf_skb_cgroup_id(skb);
    u64 *value = bpf_map_lookup_elem(&cgroup_stats, &cgroup_id);
    u64 bytes = skb->len;

    if (value) {
        __sync_fetch_and_add(value, bytes);
    } else {
        u64 init_val = bytes;
        bpf_map_update_elem(&cgroup_stats, &cgroup_id, &init_val, BPF_NOEXIST);
    }
    return TC_ACT_OK;
}