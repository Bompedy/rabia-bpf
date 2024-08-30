#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

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
    if (skb->len < sizeof(struct ethhdr)) {
        bpf_printk("Not a packet we want!\n");
        return XDP_PASS;
    }
    struct ethhdr *eth = (struct ethhdr *)(long)skb->data;

    bpf_printk("\nPacket %d: ", skb->len);
    for (int i = 0; i < ETH_ALEN; ++i) {
        bpf_printk("Source MAC address: %d", eth->h_source[i]);
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";