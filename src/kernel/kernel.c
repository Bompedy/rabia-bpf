#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct bpf_map_def SEC("maps") states = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(long),
        .max_entries = 10000000,
};

struct bpf_map_def SEC("maps") votes = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(char),
        .max_entries = 10000000,
};

struct bpf_map_def SEC("maps") proposals = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(char),
        .max_entries = 1250000,
};

struct bpf_map_def SEC("maps") input_buf = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 4096,
};

struct bpf_map_def SEC("maps") output_buf = {
        .type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 4096,
};

SEC("xdp")
int xdp_prog(struct __sk_buff *skb) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";