#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output_buf SEC(".maps");

#define PAXOS_PORT 6969
unsigned int counter = 0;
unsigned long commit_index = 0L;

unsigned char machine_address[6];
unsigned char addresses[3][6];
int interface_index;


#define print(message) bpf_ringbuf_output(&output_buf, message, sizeof(message), 0)


SEC("xdp")
int xdp_hook(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }
    struct ethhdr *in_eth = (struct ethhdr *) data;


    for (int i = 0; i < 3; ++i) {
        unsigned char* address = addresses[i];
        if (
                address[0] != machine_address[0] && address[1] != machine_address[1] && address[2] != machine_address[2]
                && address[3] != machine_address[3] && address[4] != machine_address[4] &&
                address[5] != machine_address[5]
        ) {
            in_eth->h_dest[0] = address[0];
            in_eth->h_dest[1] = address[1];
            in_eth->h_dest[2] = address[2];
            in_eth->h_dest[3] = address[3];
            in_eth->h_dest[4] = address[4];
            in_eth->h_dest[5] = address[5];
            int result = bpf_clone_redirect(ctx, ctx->ingress_ifindex, 0);
            if (result) {
                bpf_printk("Dropping packet!");
                return XDP_DROP;
            } else {
                bpf_printk("Sent packet to %d!", i);
            }
        }
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";