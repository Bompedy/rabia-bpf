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
//
//SEC("xdp")
//int xdp_hook(struct __sk_buff *skb) {
//    return XDP_PASS;
//}

#define TC_ACT_OK 0

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}
//
//SEC("action")
//int tc_action(struct __sk_buff *skb) {
//    return TC_ACT_OK;
//}
//
//SEC("tc")
//int tc(struct __sk_buff *skb) {
//    return TC_ACT_OK;
//}

char _license[] SEC("license") = "GPL";