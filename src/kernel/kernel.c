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

unsigned long last_commit_index = 0L;
unsigned long commit_index = 0L;
unsigned int acks[1000000];

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
    if (in_eth->h_proto == 0x0D0D) {
        return XDP_PASS;
    }
    unsigned char op = *((unsigned char *)data + sizeof(struct ethhdr));
    if (op == 0) { //message
        unsigned char* address = addresses[0];
        if (
                address[0] != machine_address[0] && address[1] != machine_address[1] && address[2] != machine_address[2]
                && address[3] != machine_address[3] && address[4] != machine_address[4] && address[5] != machine_address[5]
                ) { //forward
            for (int i = 0; i < 6; i++) {
                in_eth->h_source[i] = machine_address[i];
                in_eth->h_dest[i] = address[i];
            }
            return XDP_TX;
        } else { //leader
            int index = __sync_add_and_fetch(&commit_index, 1);
            for (int i = 0; i < 6; i++) {
                in_eth->h_source[i] = machine_address[i];
                in_eth->h_dest[i] = 0xFF;
            }
            *((char*) (data + sizeof(struct ethhdr))) = 1;
            *((int*) (data + sizeof(struct ethhdr) + 1)) = index;
            return XDP_TX;
        }
    } else if (op == 1) {
        for (int i = 0; i < 6; i++) {
            in_eth->h_source[i] = machine_address[i];
            in_eth->h_dest[i] = addresses[0][i];
        }
        *((char*) (data + sizeof(struct ethhdr))) = 2;
        return XDP_TX;
    } else if (op == 2) {
        unsigned long index = *((char*) (data + sizeof(struct ethhdr) + 1));
//        unsigned int ack_count = __sync_add_and_fetch(&acks[index], 1);
//        if (ack_count >= 2 && commit_index + 1 == index) while (acks[index] >= 2) {
//                //log index
//                __sync_val_compare_and_swap(&commit_index, index - 1, index);
//                index++;
//            }
        return XDP_PASS;
    }

    bpf_printk("test");


//    for (int i = 0; i < 3; ++i) {
//        unsigned char* address = addresses[i];
//        if (
//                address[0] != machine_address[0] && address[1] != machine_address[1] && address[2] != machine_address[2]
//                && address[3] != machine_address[3] && address[4] != machine_address[4] &&
//                address[5] != machine_address[5]
//        ) {
//            in_eth->h_dest[0] = address[0];
//            in_eth->h_dest[1] = address[1];
//            in_eth->h_dest[2] = address[2];
//            in_eth->h_dest[3] = address[3];
//            in_eth->h_dest[4] = address[4];
//            in_eth->h_dest[5] = address[5];
//            int result = bpf_clone_redirect(ctx, ctx->ingress_ifindex, 0);
//            if (result) {
//                bpf_printk("Dropping packet!");
//                return XDP_DROP;
//            } else {
//                bpf_printk("Sent packet to %d!", i);
//            }
//        }
//    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";