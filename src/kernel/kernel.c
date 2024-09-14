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
char paxos_log[500][1400];

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

void memcpy(char* d, char* s, int count) {

}

SEC("xdp")
int xdp_hook(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    if (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr) > data_end) return XDP_PASS;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *) data + sizeof(struct ethhdr));
        int skip = in_paxos->data_size == -1 ? 1 : 0;
        if (!skip) {
            if (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr) + in_paxos->data_size > data_end) return XDP_PASS;
            if (bpf_skb_load_bytes((char*) (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr)), 0, paxos_log[in_paxos->slot], in_paxos->data_size) < 0) {
                bpf_printk("ERRORED WHEN LOADING BYTES!");
            } else {
                bpf_printk("successfuly stored bytes!");
            }
//            __builtin_memcpy(paxos_log[in_paxos->slot], (char*) (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr)), in_paxos->data_size);
        }
//        bpf_printk("GOT PIPE SETUP PACKET: op=%d, slot=%d, next=%d, data_size=%d", in_paxos->op, in_paxos->slot, in_paxos->next, in_paxos->data_size);
        return XDP_PASS;
    }


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
}*/

SEC("tc")
int tc_hook(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    if (data + sizeof(struct ethhdr) + sizeof(struct paxos_hdr) > data_end) return TC_ACT_OK;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *)data + sizeof(struct ethhdr));
        if (in_paxos->op == INIT) {
            in_paxos->op = PROPOSE;
            in_paxos->data_size = 4;
            unsigned long long slot = in_paxos->slot;
            if (MULTI_PAXOS && node_index == 0) {
                if (bpf_clone_redirect(skb, skb->ifindex, 0)) {
                    bpf_printk("FAILED PIPE INIT: %d", slot);
                } else
                    bpf_printk("PROPOSED PIPE: %d", slot);
            }

            return TC_ACT_SHOT;
        }
    }
    return TC_ACT_OK;
}



char _license[] SEC("license") = "GPL";