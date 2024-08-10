#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 10000000);
} states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(char));
    __uint(max_entries, 10000000);
} votes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(char));
    __uint(max_entries, 1250000);
} proposals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} input_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output_buf SEC(".maps");

SEC("xdp")
int xdp_hook(struct __sk_buff *skb) {
    return XDP_PASS;
}

#define TC_ACT_OK 0

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(long));
    __uint(max_entries, 1);
} packet_count SEC(".maps");

SEC("tc")
int tc_hook(struct __sk_buff *skb) {
    int key = 0;
    long *count;

    // Retrieve the current count from the map
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        // Increment the count
        __sync_fetch_and_add(count, 1);
    } else {
        // Handle case where map lookup fails (e.g., map might be uninitialized)
        long initial_value = 1;
        bpf_map_update_elem(&packet_count, &key, &initial_value, BPF_ANY);
    }

    return TC_ACT_OK;
}


char _license[] SEC("license") = "GPL";