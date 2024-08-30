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
int xdp_hook(struct xdp_md* ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 len = data_end - data;
    bpf_printk("\nPacket %u: ", len);
    if (len < sizeof(struct ethhdr)) {
        return XDP_PASS;
    }
        struct ethhdr *eth = (struct ethhdr *) data;
        bpf_printk("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";