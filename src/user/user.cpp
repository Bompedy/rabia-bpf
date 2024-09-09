#include <bpf/libbpf.h>
#include <net/if.h>
#include <cstdlib>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <iostream>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <thread>
#include <chrono>
#include <string>
#include <cstdio>
#include <stdexcept>
#include <array>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <vector>
#include <algorithm>
#include <iomanip>
#include "gen.h"
#include <csignal>

struct address {
    std::string ip_str;
    std::string mac_str;
    unsigned char mac[6];
};

std::string mac_to_string(const unsigned char *mac, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    auto mac_addr = oss.str();
    std::replace(mac_addr.begin(), mac_addr.end(), ':', '-');
    return mac_addr;
}

// Function to get machine's IP address and MAC address for a given interface_name
address get_machine_addr(const std::string& interface_name) {
    address result;
    struct ifaddrs *ifaddr_struct = nullptr;
    struct ifaddrs *ifa = nullptr;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr_struct) == -1) {
        throw std::runtime_error("Failed to get network interfaces");
    }

    for (ifa = ifaddr_struct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (interface_name == ifa->ifa_name) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
                    result.ip_str = host;
                }
            }

            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                auto *sll = (struct sockaddr_ll *)ifa->ifa_addr;
                result.mac_str = mac_to_string(sll->sll_addr, sll->sll_halen);
                memcpy(result.mac, sll->sll_addr, sll->sll_halen);
            }
        }
    }

    freeifaddrs(ifaddr_struct);
    return result;
}

int handle_event(void* ctx, void* data, size_t size) {
    std::cout << "Log: " << reinterpret_cast<char*>(data) << std::endl;
    return 1;
}

ring_buffer* log_ring = nullptr;
kernel* skeleton = nullptr;
int interface_idx;
char* interface_name;
int tc_fd;

void cleanup() {
    struct bpf_tc_hook hook = {};
    hook.sz = sizeof(hook);
    hook.attach_point = BPF_TC_EGRESS;
    hook.ifindex = interface_idx;
    bpf_xdp_detach(interface_idx, 0, nullptr);
    bpf_tc_hook_destroy(&hook);
    ring_buffer__free(log_ring);
    kernel__detach(skeleton);
    kernel__destroy(skeleton);
}

void termination_handler(int signal) {
    std::cout << "Received shutdown signal: " << signal << std::endl;
    cleanup();
    std::cout << "Exiting program!" << std::endl;
    std::exit(EXIT_SUCCESS);
}

void send_packet(
        const int socket,
        const unsigned char* source,
        const unsigned char* dest,
        const unsigned char* data,
        const int in_size
) {
    auto *buffer = (uint8_t *) malloc(sizeof(struct ethhdr) + in_size);
    auto *eth = (struct ethhdr*) buffer;

    memset(eth, 0, sizeof(struct ethhdr));
    memcpy(eth->h_dest, dest, ETH_ALEN);
    memcpy(eth->h_source, source, ETH_ALEN);
    memcpy(buffer + sizeof(struct ethhdr), data, in_size);
    eth->h_proto = htons(0xD0D0);

    struct sockaddr_ll sadr_ll{};
    memset(&sadr_ll, 0, sizeof(struct sockaddr_ll));
    sadr_ll.sll_family = AF_PACKET;
    sadr_ll.sll_protocol = htons(0xD0D0);
    sadr_ll.sll_ifindex = interface_idx;
    sadr_ll.sll_halen = ETH_ALEN;
    memcpy(sadr_ll.sll_addr, dest, ETH_ALEN);

    auto unsent = sizeof(struct ethhdr) + in_size;
    while (unsent != 0) {
        const auto written = sendto(socket, buffer, unsent, 0, (const struct sockaddr *) &sadr_ll, sizeof(struct sockaddr_ll));
        std::cout << "Sent 1 " << written << std::endl;
        if (written < 0) {
            std::cerr << "ERROR WRITING TO RAW SOCKET!: " << written << std::endl;
            break;
        }

        std::cout << "Sent 2 " << written << std::endl;
        unsent -= written;
    }

    std::cout << "Wrote out packet!" << std::endl;
}

unsigned char BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const unsigned char INIT = 0;
const unsigned char PROPOSE = 1;
const unsigned char ACK = 2;

int main() {
    interface_name = getenv("INTERFACE");
    if (!interface_name) {
        std::cerr << "Interface env var is not set!" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << interface_name << std::endl;

    const auto machine_address = get_machine_addr(interface_name);
    std::cout << "This machines address: " << machine_address.mac_str << ", " << machine_address.ip_str << std::endl;

    std::vector<address> pod_addresses = {
            {"10.10.1.1", "0c:42:a1:dd:57:fc", {0x0c, 0x42, 0xa1, 0xdd, 0x57, 0xfc}},
            {"10.10.1.2", "0c:42:a1:dd:5f:74", {0x0c, 0x42, 0xa1, 0xdd, 0x5f, 0x74}},
            {"10.10.1.3", "0c:42:a1:dd:5e:80", {0x0c, 0x42, 0xa1, 0xdd, 0x5e, 0x80}}
    };

    if (pod_addresses.empty()) {
        std::cout << "Can't find any ips!" << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& ip : pod_addresses) {
        std::cout << "Pod IP,Mac: " << ip.ip_str << ", " << ip.mac_str  << std::endl;
    }

    skeleton = kernel__open_and_load();
    if (!skeleton) {
        std::cerr << "Failed to load bpf skeleton" << std::endl;
        return EXIT_FAILURE;
    }

    interface_idx = if_nametoindex(interface_name);
    if (interface_idx == 0) {
        cleanup();
        return EXIT_FAILURE;
    }

    const auto xdp_fd = bpf_program__fd(skeleton->progs.xdp_hook);
    if (bpf_xdp_attach(interface_idx, xdp_fd, 0, nullptr) < 0) {
        cleanup();
        return EXIT_FAILURE;
    }
    std::cout << "Attached to xdp!" << std::endl;

    tc_fd = bpf_program__fd(skeleton->progs.tc_hook);
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    hook.sz = sizeof(hook);
    hook.attach_point = BPF_TC_EGRESS;
    hook.ifindex = interface_idx;
    opts.sz = sizeof(opts);
    opts.prog_fd = tc_fd;

    if (bpf_tc_attach(&hook, &opts)) {
        cleanup();
        return EXIT_FAILURE;
    }
    std::cout << "Attached to tc!" << std::endl;

    const auto log_ring_fd = bpf_object__find_map_fd_by_name(skeleton->obj, "output_buf");
    if (log_ring_fd < 0) {
        cleanup();
        return EXIT_FAILURE;
    }

    log_ring = ring_buffer__new(log_ring_fd, handle_event, nullptr, nullptr);


    for (int i = 0; i < pod_addresses.size(); ++i) {
        const auto address = pod_addresses[i];
        memcpy(skeleton->bss->addresses[i], address.mac, ETH_ALEN);
    }

    skeleton->bss->interface_index = interface_idx;
    memcpy(skeleton->bss->machine_address, machine_address.mac, ETH_ALEN);

    std::signal(SIGINT, termination_handler);
    std::signal(SIGTERM, termination_handler);


    std::thread write_thread([&]() {
        const int sock_write = socket(AF_PACKET, SOCK_RAW, htons(0xD0D0));
        if (sock_write < 0) {
            printf("errno=%d\n", errno);
            return EXIT_FAILURE;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
        if (setsockopt(sock_write, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            printf("errno=%d\n", errno);
            return EXIT_FAILURE;
        }

        send_packet(sock_write, machine_address.mac, BROADCAST, &INIT, 1);


        while (true) {
//            send_packet(sock_write, machine_address.mac, BROADCAST, , 1);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    });
    std::thread poll_thread([&]() {
        while (true) {
            const auto error = ring_buffer__poll(log_ring, 200);
            if (error < 0) std::cerr << "Error polling!" << std::endl;
        }
    });
    write_thread.join();
    poll_thread.join();
    return 0;
}
