#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
//#include <arpa/inet.h>

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

static inline unsigned short htons(unsigned short host) {
    return (unsigned short) ((host >> 8) | (host << 8));
}

struct rabia_packet {
    unsigned long slot
};

static __always_inline int rabia_update(void* data) {

}

#define RABIA_PORT 12345
#define LEN_HDR sizeof(struct ethhdr) + sizeof(struct iphdr)
SEC("xdp")
int xdp_hook(struct __sk_buff* skb) {
    void* const end = skb->data_end;

    // If the packet is too small to have ip header.
    if (skb->data + LEN_HDR > end)
        return XDP_PASS;

    struct ethhdr* const eth_header = skb->data;
    struct iphdr* const ip_header = skb->data + sizeof(struct iphdr);

    // not sure if can use htons
    if (eth_header->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    if (ip_header->protocol != IPPROTO_RAW)
        return XDP_PASS;

    const int length = ip_header->tot_len;
    void* const data = skb->data + LEN_HDR
    if (data + length > end)
        return XDP_PASS;





    return XDP_PASS;
}

//#define TC_ACT_OK 0
//
//SEC("tc")
//int tc_hook(struct __sk_buff *skb) {
//    int key = 0;
//    long *count;
//    // Retrieve the current count from the map
//    count = bpf_map_lookup_elem(&packet_count, &key);
//    if (count) {
//        // Increment the count
//        __sync_fetch_and_add(count, 1);
//    } else {
//        // Handle case where map lookup fails (e.g., map might be uninitialized)
//        long initial_value = 1;
//        bpf_map_update_elem(&packet_count, &key, &initial_value, BPF_ANY);
//        // auto complete work?
//
//    }
//
//    return TC_ACT_OK;
//}


char _license[] SEC("license") = "GPL";