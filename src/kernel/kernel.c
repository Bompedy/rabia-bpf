#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_common.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output_buf SEC(".maps");

#define PAXOS_PORT 6969
unsigned int counter = 0;
unsigned long commit_index = 0L;


#define print(message) bpf_ringbuf_output(&output_buf, message, sizeof(message), 0)


SEC("xdp")
int xdp_hook(struct __sk_buff* skb) {
    counter += 1;
    print("hello");
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";