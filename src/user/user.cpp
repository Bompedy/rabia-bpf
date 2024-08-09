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

int main() {
    const auto interface = getenv("INTERFACE");
    if (!interface) {
        std::cerr << "Interface env var is not set!" << std::endl;
        return EXIT_FAILURE;
    }

    const auto obj = bpf_object__open_file("./obj/kernel.o", nullptr);
    if (!obj) {
        std::cerr << "Failed to open BPF object file: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        std::cerr << "Failed to load BPF object: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    const auto program = bpf_object__find_program_by_title(obj, "xdp");
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

    if (bpf_set_link_xdp_fd(interface_index, bpf_fd, 0) < 0) {
        std::cerr << "Failed to attach XDP program to interface: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Attached to XDP on " << interface << std::endl;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "Error creating socket: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }

    struct sockaddr_ll addr{};
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = interface_index;

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        std::cerr << "Error binding socket: " << std::strerror(errno) << std::endl;
        close(fd);
        return EXIT_FAILURE;
    }

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ifr.ifr_ifindex = interface_index;

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr)) < 0) {
        std::cerr << "Error setting socket options: " << std::strerror(errno) << std::endl;
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);
    close(bpf_fd);
    std::cout << "Exiting program!" << std::endl;

    return 0;
}