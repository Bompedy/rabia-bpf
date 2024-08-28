#include <bpf/libbpf.h>
#include <net/if.h>
#include <cstdlib>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <iostream>
#include <unistd.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <cstring>
#include <cerrno>
#include <thread>
#include <chrono>
#include <string>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <stdexcept>
#include <array>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>

struct address {
    std::string ip_str;
    std::string mac_str;
    uint8_t mac[6];
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
            address{"10.0.0.1", ""},
            address{"10.0.0.1", ""},
            address{"10.0.0.1", ""}
    };

    if (pod_addresses.empty()) {
        std::cout << "Can't find any ips!" << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& ip : pod_addresses) {
        std::cout << "Pod IP,Mac: " << ip.ip_str << ", " << ip.mac_str  << std::endl;
    }

//    char command[256];
//    snprintf(command, sizeof(command),"tc qdisc add dev %s clsact", interface);
//    if (system(command) != 0) {
//        fprintf(stderr, "Failed to execute command: %s\n", strerror(errno));
//        return EXIT_FAILURE;
//    }
//
//    printf("Successfully added qdisc to %s\n", interface);

    const auto obj = bpf_object__open_file("./obj/kernel.o", nullptr);
//    obj->bbs
    if (!obj) {
        std::cerr << "Failed to open BPF object file: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Loading object" << std::endl;
    if (bpf_object__load(obj)) {
        std::cerr << "Failed to load BPF object: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Loaded" << std::endl;
    const auto program = bpf_object__find_program_by_name(obj, "xdp_hook");
    if (!program) {
        std::cerr << "Failed to find BPF program: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    const auto bpf_fd = bpf_program__fd(program);
    const auto interface_index = if_nametoindex(interface);
    if (interface_index == 0) {
        std::cerr << "Failed to find interface: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Got index: " << interface_index << std::endl;
    if (bpf_xdp_attach(interface_index, bpf_fd, 0, nullptr) < 0) {
        std::cerr << "Failed to attach XDP program to interface: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Attached to XDP on " << interface << std::endl;

//    const bpf_map* addresses_fd = bpf_object__find_map_by_name(obj, "address_array");
//    for (int i = 0; i < pod_addresses.size(); ++i) {
//        unsigned char it = i;
//        std::cout << bpf_map__update_elem(addresses_fd, &it, 1, pod_addresses[i].ip_str.c_str(), pod_addresses[i].ip_str.size(), 0) << std::endl;
//    }

    while (true) {
//        if (sendto(fd, &packet, 14, 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
//            std::cerr << "Error sending packet: " << std::strerror(errno) << std::endl;
//        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }


//    const auto tc_program = bpf_object__find_program_by_name(obj, "tc_hook");
//    if (!tc_program) {
//        std::cerr << "Failed to find TC program: " << std::strerror(errno) << std::endl;
//        return EXIT_FAILURE;
//    }
//    const auto tc_fd = bpf_program__fd(tc_program);
//
//    struct bpf_tc_hook hook = {};
//    struct bpf_tc_opts opts = {};
//    hook.sz = sizeof(hook);
//    hook.attach_point = BPF_TC_EGRESS;
//    hook.ifindex = interface_index;
//    opts.sz = sizeof(opts);
//    opts.prog_fd = tc_fd;
//
//    if (bpf_tc_attach(&hook, &opts)) {
//        std::cerr << "Failed to attach TC program to interface: " << std::strerror(errno) << std::endl;
//        return EXIT_FAILURE;
//    }
//    std::cout << "Attached to tc!" << std::endl;




//    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//    if (fd < 0) {
//        std::cerr << "Error creating socket: " << std::strerror(errno) << std::endl;
//        return EXIT_FAILURE;
//    }
//    struct sockaddr_ll addr{};
//    memset(&addr, 0, sizeof(addr));
//    addr.sll_family = AF_PACKET;
//    addr.sll_protocol = htons(ETH_P_ALL);
//    addr.sll_ifindex = interface_index;
//    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
//        std::cerr << "Error binding socket: " << std::strerror(errno) << std::endl;
//        close(fd);
//        return EXIT_FAILURE;
//    }
//    struct ifreq ifr{};
//    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
//    ifr.ifr_ifindex = interface_index;
//    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr)) < 0) {
//        std::cerr << "Error setting socket options: " << std::strerror(errno) << std::endl;
//        close(fd);
//        return EXIT_FAILURE;
//    }

//    const auto mac = machine_address.mac;
//    const auto dmac = pod_addresses[0].ip_str.compare(machine_address.ip_str) == 0 ? pod_addresses[1].mac : pod_addresses[0].mac;
//    std::cout << "MAc: " << mac << ", Dest: " << dmac << std::endl;
//
//
//    char packet[1000];
//    packet.ether_type = htons(ETH_P_IP);
//
//    const auto log_ring_fd = bpf_object__find_map_fd_by_name(obj, "output_buf");
//    if (log_ring_fd < 0) {
//        std::cerr << "Can't open bpf map" << std::endl;
//        return EXIT_FAILURE;
//    }
//
//    const auto log_ring = ring_buffer__new(log_ring_fd, handle_event, nullptr, nullptr);
//    std::cout << "Got log ring: " << log_ring << std::endl;
//
//    std::thread thread([&]() {
//        while (true) {
//            const auto error = ring_buffer__poll(log_ring, 200);
//            if (error < 0) std::cerr << "Error polling!" << std::endl;
//        }
//    });
//

//    close(fd);
    close(bpf_fd);
    std::cout << "Exiting program!" << std::endl;
    return 0;
}
