#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
struct bpf_map_def SEC("maps") packet_count_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = 1,
};

SEC("xdp")
int xdp_prog(struct __sk_buff *skb) {
    int key = 0;
    long *value = bpf_map_lookup_elem(&packet_count_map, &key);
    if (value) __sync_fetch_and_add(value, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";