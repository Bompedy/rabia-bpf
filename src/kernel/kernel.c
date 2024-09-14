#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#define MENCIUS_REVISITED 0
#define PAXOS_HELPER 0
#define MULTI_PAXOS 1

#define INIT 0
#define PROPOSE 1
#define ACK 2

#define NUM_PIPES 20
#define LOG_SIZE 50000
#define DATA_SIZE 1400
#define NODES 3
#define MAJORITY (NODES/2 + 1)


unsigned char machine_address[6];
unsigned char addresses[NODES][6];
unsigned char node_index;

char data_log[LOG_SIZE][DATA_SIZE];
unsigned long long acks[LOG_SIZE];
unsigned long long committed = 0;
unsigned long long consumed = 0;

struct paxos_hdr {
    unsigned char op;
    unsigned long long slot;
    unsigned long long next;
    int data_size;
};

const int HEADER_SIZE = (sizeof(struct ethhdr) + sizeof(struct paxos_hdr));

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
    if (data + HEADER_SIZE > data_end) return XDP_PASS;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *) data + sizeof(struct ethhdr));
        if (in_paxos->op == PROPOSE) {
            if (data + HEADER_SIZE + in_paxos->data_size > data_end) return XDP_PASS;
            unsigned long long current;
            do { current = __sync_fetch_and_add(&committed, 0); }
            while (in_paxos->next > current && __sync_val_compare_and_swap(&committed, current, in_paxos->next) == current);

            if (in_paxos->data_size > 0 && in_paxos->data_size < 1400 &&
                    bpf_skb_load_bytes((char *) (data + HEADER_SIZE), 0, data_log[in_paxos->slot], in_paxos->data_size) < 0
            ) {
                bpf_printk("ERRORED WHEN STORING BYTES!");
            } else {
                for (int i = 0; i < 6; ++i) {
                    in_eth->h_dest[i] = MULTI_PAXOS ? in_eth->h_source[i] : addresses[0][i];
                    in_eth->h_source[i] = machine_address[i];
                }
                in_paxos->op = ACK;
                return XDP_TX;
            }

        } else if (in_paxos->op == ACK) {
            unsigned long long slot = in_paxos->slot;
            unsigned int acked = __sync_fetch_and_add(&acks[slot], 1);
            if (acked == MAJORITY) {
                unsigned long long current;
                in_paxos->next = current = __sync_fetch_and_add(&committed, 0);
                for (unsigned long long i = current + 1; i <= slot; ++i) {
                    if (__sync_fetch_and_add(&acks[i], 0) >= MAJORITY) in_paxos->next = i;
                    else break;
                }

                while (in_paxos->next > current && __sync_val_compare_and_swap(&committed, current, in_paxos->next) == current) {
                    current = __sync_fetch_and_add(&committed, 0);
                }

                if (MULTI_PAXOS || slot % node_index == 0) {
                    in_paxos->op = PROPOSE;
                    in_paxos->slot = (slot + NUM_PIPES);

                    for (int i = 0; i < 6; ++i) {
                        in_eth->h_dest[i] = 0xFF;
                        in_eth->h_source[i] = machine_address[i];
                    }

                    // poll or skip, update our log
                    return XDP_TX;
                }
            }

        }
        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("tc")
int tc_hook(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    if (data + HEADER_SIZE > data_end) return TC_ACT_OK;
    struct ethhdr *in_eth = (struct ethhdr *) data;
    if (in_eth->h_proto == htons(0xD0D0)) {
        struct paxos_hdr *in_paxos = (struct paxos_hdr*) ((unsigned char *)data + sizeof(struct ethhdr));
        if (in_paxos->op == INIT) {
            in_paxos->op = PROPOSE;
            in_paxos->data_size = -1; // for skip?
            unsigned long long slot = in_paxos->slot;
            if ((MULTI_PAXOS && node_index == 0) || (PAXOS_HELPER && node_index % slot == 0)) {
                // poll or skip, update our log
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