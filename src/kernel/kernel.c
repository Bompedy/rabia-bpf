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
//    if (skb->len < sizeof(struct ethhdr)) {
//        bpf_printk("Not a packet we want!\n");
//        return XDP_PASS;
//    }

//    struct ethhdr eth;
//    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
//        bpf_printk("Failed to load Ethernet header\n");
//        return XDP_PASS;
//    }

    struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
//    bpf_printk("\nPacket %d: ", skb->len);
    bpf_printk("Source MAC address: %d:%d:%d:%d:%d:%d\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";