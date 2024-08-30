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
    __u64 data[ETH_ALEN];
    int len = 0;

    for (int i = 0; i < ETH_ALEN; ++i) {
        data[i] = eth->h_source[i];
    }
    char mac_str[18];

    bpf_snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", data, sizeof(data));
    bpf_printk("Source MAC address: %s\n", mac_str);

//    print("Packet: ");
//    if (skb->len < sizeof(struct ethhdr)) {
//        print("Not a packet we want!");
//        return XDP_PASS;
//    }
//
//    struct ethhdr *eth = (struct ethhdr *)(long)skb->data;
//    print("Converted to eth header!");
//
////    struct ethhdr eth;
////    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
//////        print("couldn't load bytes!");
////        return XDP_PASS;
////    }
//
//    char mac_str[18];
//    __u64 data[ETH_ALEN];
//    int len = 0;
//
//    for (int i = 0; i < ETH_ALEN; ++i) {
//        data[i] = eth->h_source[i];
//    }
//
////    len = bpf_snprintf(mac_str, sizeof(mac_str),
////                       "%02x:%02x:%02x:%02x:%02x:%02x",
////                       data, sizeof(__u64) * ETH_ALEN);
////
////    // Ensure null-termination
////    mac_str[len] = '\0';
////
////
////    print(mac_str);
//
//    print("Complete!");
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";