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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} request_buf SEC(".maps");

#define PAXOS_PORT 6969

#define NUM_PIPES 20

#define MENCIUS_REVISITED 0
#define PAXOS_HELPER 0
#define MULTI_PAXOS 1

#define INIT 0
#define PROPOSE 1
#define ACK 2

unsigned int consumed = 0;
unsigned int committed = 0;
unsigned int acks[1000000];


unsigned char machine_address[6];
unsigned char addresses[3][6];
unsigned char node_index;


#define print(message) bpf_ringbuf_output(&output_buf, message, sizeof(message), 0)

struct paxos_hdr {
    unsigned char op;
    unsigned long long slot;
    unsigned long long next;
    int data_size;
};

unsigned short htons(unsigned short value) {
    unsigned short result;
    unsigned char *result_ptr = (unsigned char *)&result;
    unsigned char *host_ptr = (unsigned char *)&value;

    if (*(unsigned char *)&value == (value & 0xFF)) {
        result_ptr[0] = host_ptr[1];
        result_ptr[1] = host_ptr[0];
    } else {
        result = value;
    }

    return result;
}


SEC("xdp")
int xdp_hook(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    if (data + sizeof(struct ethhdr) > data_end) return XDP_DROP;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        if (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr) > data_end) return XDP_DROP;
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *) data + sizeof(struct ethhdr));
//        bpf_printk("GOT PIPE SETUP PACKET: op=%d, slot=%d, next=%d, data_size=%d", in_paxos->op, in_paxos->slot, in_paxos->next, in_paxos->data_size);
        return XDP_PASS;
    }

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
/*
 * log: array<bytes>
acks: array<int>
committed: int
consumed: int

on_propose(slot: int, message: bytes, next: int) {
  //put the proposal into the log.
  log[slot] = message
  //MR doesn't need "learn step" although it could use it without harm.
  if (!MENCIUS_REVISITED) {
    //he we learn about where commit was moved up to so we move it.
    current: int
    do {
      current = atomic_load(committed)
    } while (next > current && !atomic_cas(committed, current, next))
    //PH respond to static leader rather than sender (assumed leader for MP)
    if (PAXOS_HELPER) respond_leader_ack(slot) else respond_ack(slot)
  } else respond_multicast_ack(slot) //Mencius multicast to let others learn.
}

on_ack(slot: int) {
  //record the ack for this slot
  previous = atomic_add(acks[slot], 1)
  if (previous != MAJORITY -1) return;
  //TODO: maybe we can move this code to a timer if it's too slow.
  //find out how many slots we can commit (doesn't commit over holes)
  current = next = atomic_load(committed)
  for (i in comitted+1..slot)
    if (atomic_load(acks[i]) >= MAJORITY)
      next = i
    else break
  //Simply try to move forward commit if we were able to.
  while (next > current && !atomic_cas(committed, current, next))
    current = atomic_load(committed)
  //if we own the slot (MP owns no matter what) then propose next and let learn.
  if (MULTI_PAXOS || slot % THIS_NODE == 0)
    multicast_propose(pq.poll() ?? SKIP, slot += NUM_PIPES, next)
}


//MP has all pipes on leader, PH and MR distribute them evenly.
for (i in NUM_PIPES)
  if (MULTI_PAOXS || i % THIS_NODE == 0)
     multicast_propose(pq.poll() ?? SKIP, i, 0)
*/

// eth header
// sender 6
// receiver 6
// protocol 2

// 1400 - 35
// 1365

// consensus header
// op = INIT, PROPOSE, ACK 1
// next = committed up to 8
// slot 8
// bytes size 4
// bytes message undefined


int initialized_pipes;

SEC("tc")
int tc_hook(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    if (data + sizeof(struct ethhdr) + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *)data + sizeof(struct ethhdr));
        if (in_paxos->op == INIT) {
            in_paxos->op = PROPOSE;
            if (MULTI_PAXOS) {
                if (bpf_clone_redirect(skb, skb->ifindex, 0)) {
//                    bpf_printk("FAILED PIPE INIT: %d", in_paxos->slot);
                }
            }

            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
}



char _license[] SEC("license") = "GPL";