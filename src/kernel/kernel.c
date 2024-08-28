#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf_common.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} output_buf SEC(".maps");


//struct {
//    __uint(type, BPF_MAP_TYPE_ARRAY);
//    __type(key, unsigned char);
//    __type(value, unsigned char[4]);
//    __uint(max_entries, 10);
//} address_array SEC(".maps");

#define PAXOS_PORT 6969
unsigned long commit_index = -1;
unsigned long something[250];


struct address {
    char host[4];
};

char max_addresses = 0;
struct address addresses[10];


#define print(message) bpf_ringbuf_output(&output_buf, message, sizeof(message), 0)


SEC("xdp")
int xdp_hook(struct __sk_buff* skb) {
    int error;
    int index = 0;
//    bpf_map_lookup_elem(&addresses, 0);
//    while (error == 0) {
//        error = bpf_map_lookup_elem(&addresses, 0);
//    }
    if (__sync_bool_compare_and_swap(&commit_index, -1, 0)) {

        //init shit
        return XDP_PASS;
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";