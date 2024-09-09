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
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output_buf SEC(".maps");

#define PAXOS_PORT 6969

#define NUM_PIPES 50

#define MENCIUS_REVISITED 0
#define PAXOS_HELPER 1
#define MULTI_PAXOS 2

#define INIT 0
#define PROPOSE 1
#define ACK 2

unsigned int consumed = 0;
unsigned int committed = 0;
unsigned int acks[1000000];


unsigned char machine_address[6];
unsigned char addresses[3][6];
int interface_index;


#define print(message) bpf_ringbuf_output(&output_buf, message, sizeof(message), 0)


SEC("xdp")
int xdp_hook(struct xdp_md *ctx) {
    print("Came here!");
//    void *data = (void *) (long) ctx->data;
//    void *data_end = (void *) (long) ctx->data_end;
//    if (data + sizeof(struct ethhdr) > data_end) {
//        return XDP_DROP;
//    }
//    struct ethhdr *in_eth = (struct ethhdr *) data;
//    if (in_eth->h_proto == 0x0D0D) {
//        return XDP_PASS;
//    }
//    unsigned char *op = ((unsigned char *)data + sizeof(struct ethhdr));
//    unsigned int *slot = ((unsigned int *)data + sizeof(struct ethhdr) + 1);
//    if (*op == PROPOSE) {
//        unsigned int next = *((unsigned int *)data + sizeof(struct ethhdr) + 5);
//        int current;
//        do {
//            current = committed;
//        } while (next > current && !__sync_val_compare_and_swap(&committed, current, next));
//        if (PAXOS_HELPER) {
//            *op = ACK;
//            for (int i = 0; i < 6; i++) {
//                in_eth->h_source[i] = machine_address[i];
//                in_eth->h_dest[i] = addresses[0][i];
//            }
//
//        }
//    } else if (*op == ACK) {
//
//    }

//    if (op == 0) { //message
//        unsigned char* address = addresses[0];
//        if (
//                address[0] != machine_address[0] && address[1] != machine_address[1] && address[2] != machine_address[2]
//                && address[3] != machine_address[3] && address[4] != machine_address[4] && address[5] != machine_address[5]
//        ) { //forward
//            for (int i = 0; i < 6; i++) {
//                in_eth->h_source[i] = machine_address[i];
//                in_eth->h_dest[i] = address[i];
//            }
//            return XDP_TX;
//        } else { //leader
//            int index = __sync_add_and_fetch(&commit_index, 1);
//            for (int i = 0; i < 6; i++) {
//                in_eth->h_source[i] = machine_address[i];
//                in_eth->h_dest[i] = 0xFF;
//            }
//            *((char*) (data + sizeof(struct ethhdr))) = 1;
//            *((int*) (data + sizeof(struct ethhdr) + 1)) = index;
//            return XDP_TX;
//        }
//    } else if (op == 1) {
//        for (int i = 0; i < 6; i++) {
//            in_eth->h_source[i] = machine_address[i];
//            in_eth->h_dest[i] = addresses[0][i];
//        }
//        *((char*) (data + sizeof(struct ethhdr))) = 2;
//        return XDP_TX;
//    } else if (op == 2) {
//        unsigned long index = *((char*) (data + sizeof(struct ethhdr) + 1));
////        unsigned int ack_count = __sync_add_and_fetch(&acks[index], 1);
////        if (ack_count >= 2 && commit_index + 1 == index) while (acks[index] >= 2) {
////                //log index
////                __sync_val_compare_and_swap(&commit_index, index - 1, index);
////                index++;
////            }
//        return XDP_PASS;
//    }


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


SEC("tc")
int tc_hook(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == 0x0D0D) {
        if (data + sizeof(struct ethhdr) + sizeof(unsigned char) > data_end) return TC_ACT_OK;
        unsigned char op = *((unsigned char *)data + sizeof(struct ethhdr));
        if (op == INIT) {
            for (int i = 0; i < 6; i++) {
                in_eth->h_source[i] = machine_address[i];
                in_eth->h_dest[i] = 0xFF;
            }
            for (int i = 0; i < NUM_PIPES; ++i) {
                print("Sending out!");
                bpf_clone_redirect(skb, skb->ifindex, 0);
            }
//
            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
}

/*
 * libbpf: prog 'tc_hook': BPF program load failed: Permission denied
libbpf: prog 'tc_hook': -- BEGIN PROG LOAD LOG --
0: R1=ctx(off=0,imm=0) R10=fp0
; int tc_hook(struct __sk_buff *skb) {
0: (b7) r0 = 0                        ; R0_w=0
; void *data = (void *) (long) skb->data;
1: (61) r2 = *(u32 *)(r1 +76)         ; R1=ctx(off=0,imm=0) R2_w=pkt(off=0,r=0,imm=0)
; if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
2: (bf) r3 = r2                       ; R2_w=pkt(off=0,r=0,imm=0) R3_w=pkt(off=0,r=0,imm=0)
3: (07) r3 += 14                      ; R3_w=pkt(off=14,r=0,imm=0)
; void *data_end = (void *) (long) skb->data_end;
4: (61) r1 = *(u32 *)(r1 +80)         ; R1_w=pkt_end(off=0,imm=0)
; if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
5: (2d) if r3 > r1 goto pc+29         ; R1_w=pkt_end(off=0,imm=0) R3_w=pkt(off=14,r=14,imm=0)
; if (in_eth->h_proto == 0x0D0D) {
6: (71) r1 = *(u8 *)(r2 +12)          ; R1_w=scalar(umax=255,var_off=(0x0; 0xff)) R2_w=pkt(off=0,r=14,imm=0)
7: (71) r4 = *(u8 *)(r2 +13)          ; R2_w=pkt(off=0,r=14,imm=0) R4_w=scalar(umax=255,var_off=(0x0; 0xff))
8: (67) r4 <<= 8                      ; R4_w=scalar(umax=65280,var_off=(0x0; 0xff00))
9: (4f) r4 |= r1                      ; R1_w=scalar(umax=255,var_off=(0x0; 0xff)) R4_w=scalar()
; if (in_eth->h_proto == 0x0D0D) {
10: (55) if r4 != 0xd0d goto pc+24    ; R4_w=3341
; unsigned char op = *((unsigned char *)data + sizeof(struct ethhdr));
11: (71) r1 = *(u8 *)(r3 +0)
invalid access to packet, off=14 size=1, R3(id=0,off=14,r=14)
R3 offset is outside of the packet
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'tc_hook': failed to load: -13
libbpf: failed to load object 'kernel'
libbpf: failed to load BPF skeleton 'kernel': -13
Failed to load bpf skeleton*/


char _license[] SEC("license") = "GPL";