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
//    print("Packet: ");
    if (skb->len < sizeof(struct ethhdr)) {
        print("Not a packet we want!");
        return XDP_PASS;
    }

    struct ethhdr eth;
    int bytes = bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

//    struct ethhdr eth;
//    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
////        print("couldn't load bytes!");
//        return XDP_PASS;
//    }

//
//    for (int i = 0; i < ETH_ALEN; ++i) {
//        print(&eth.h_source[i]);
//    }
//    print("Complete!");
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";