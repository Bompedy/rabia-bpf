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

struct address {
    std::string ip_str;
    std::string mac_str;
    uint8_t mac[6];
};

const uint8_t MULTICAST_ADDR[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

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

// Function to get machine's IP address and MAC address for a given interface
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
            }
        }
    }

    freeifaddrs(ifaddr_struct);
    return result;
}

uint16_t checksum(uint16_t* buffer, int word) {
    uint64_t sum;
    for(sum = 0; word > 0; word--)
        sum += htons(*(buffer)++);
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum >> 16);
    return (uint16_t) (~sum);
}

int handle_event(void* ctx, void* data, size_t size) {
    std::cout << "Log: " << reinterpret_cast<char*>(data) << std::endl;
    return 1;
}

int main() {
    const auto interface = getenv("INTERFACE");
    if (!interface) {
        std::cerr << "Interface env var is not set!" << std::endl;
        return EXIT_FAILURE;
    }

    const auto machine_address = get_machine_addr(interface);
    std::cout << "This machines address: " << machine_address.mac_str << ", " << machine_address.ip_str << std::endl;


    std::vector<address> pod_addresses = {
            address{"10.10.1.1", "b0-26-28-74-d4-b1"}
//            ,
//            address{"10.0.0.1", ""},
//            address{"10.0.0.1", ""}
    };

    if (pod_addresses.empty()) {
        std::cout << "Can't find any ips!" << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& ip : pod_addresses) {
        std::cout << "Pod IP,Mac: " << ip.ip_str << ", " << ip.mac_str  << std::endl;
    }


    const auto skeleton = kernel__open_and_load();
    if (!skeleton) {
        std::cerr << "Failed to load bpf skeleton" << std::endl;
        return EXIT_FAILURE;
    }

    const auto interface_index = if_nametoindex(interface);
    if (interface_index == 0) {
        std::cerr << "Failed to find interface: " << std::strerror(errno) << std::endl;
        kernel__destroy(skeleton);
        return EXIT_FAILURE;
    }

    const auto xdp_fd = bpf_program__fd(skeleton->progs.xdp_hook);
    if (bpf_xdp_attach(interface_index, xdp_fd, 0, nullptr) < 0) {
        std::cerr << "Failed to attach XDP program to interface: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

//    const auto attach_error = kernel__attach(skeleton);
//    if (attach_error) {
//        std::cerr << "Failed to attach skeleton: " << strerror(-attach_error) << std::endl;
//        kernel__destroy(skeleton);
//        return EXIT_FAILURE;
//    }

    const auto log_ring_fd = bpf_object__find_map_fd_by_name(skeleton->obj, "output_buf");
    if (log_ring_fd < 0) {
        std::cerr << "Can't open bpf map" << std::endl;
        kernel__destroy(skeleton);
        return EXIT_FAILURE;
    }
    const auto log_ring = ring_buffer__new(log_ring_fd, handle_event, nullptr, nullptr);
    std::cout << "Got log ring: " << log_ring << std::endl;
//    std::thread thread([&]() {
//        while (true) {
//            std::cout << "poll it" << std::endl;
//            const auto error = ring_buffer__poll(log_ring, 200);
//            std::cout << "got nothing" << std::endl;
//            if (error < 0) std::cerr << "Error polling!" << std::endl;
//        }
//    });
//    thread.join();
//    std::thread thread_read([&]() {
//
//    });
//    std::thread thread_write([&]() {
//
//    });




    skeleton->bss->counter = 70;
    std::thread write_thread([&]() {
        while (true) {
            int sock_write = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (sock_write < 0) {
                printf("errno=%d\n", errno);
                return EXIT_FAILURE;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
            if (setsockopt(sock_write, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
                printf("errno=%d\n", errno);
                return EXIT_FAILURE;
            }

            struct ethhdr eth;
            memset(&eth, 0, sizeof(eth));
            memset(eth.h_dest, 0xFF, ETH_ALEN);
            const uint8_t hardcoded_mac[ETH_ALEN] = { 0x14, 0x58, 0xd0, 0x58, 0xdf, 0xe3 };
            memcpy(eth.h_source, hardcoded_mac, ETH_ALEN);
            eth.h_proto = htons(0xD0D0);

            int size = sizeof(struct ethhdr) + 65;
            uint8_t *buffer = (uint8_t*) malloc(size);
            memset(buffer, 0, sizeof(struct ethhdr) + 65);
            memcpy(buffer, &eth, sizeof(eth));


//            struct ethhdr *eth = (struct ethhdr*) buffer;

            struct sockaddr_ll sadr_ll;
            memset(&sadr_ll, 0, sizeof(struct sockaddr_ll));
            sadr_ll.sll_family = AF_PACKET;
            sadr_ll.sll_protocol = htons(0xD0D0);
            sadr_ll.sll_ifindex = interface_index;
            sadr_ll.sll_halen = ETH_ALEN;
            memset(sadr_ll.sll_addr, 0xFF, ETH_ALEN);

            int sent = sendto(sock_write, buffer, size, 0, (const struct sockaddr*) &sadr_ll, sizeof(struct sockaddr_ll));
            if(sent < 0) {
                printf("sent=%d, errno=%d\n", sent, errno);
                return EXIT_FAILURE;
            }
            printf("sent=%d\n", sent);
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
    std::cout << "Does it go here1?" << std::endl;
    poll_thread.join();
    std::cout << "Does it go here?" << std::endl;


//    while (true) {
//        std::cout << "test" << std::endl;
//        std::this_thread::sleep_for(std::chrono::seconds(3));
//    }

    ring_buffer__free(log_ring);
    kernel__detach(skeleton);
    kernel__destroy(skeleton);
    std::cout << "Exiting program!" << std::endl;
    return 0;
}
