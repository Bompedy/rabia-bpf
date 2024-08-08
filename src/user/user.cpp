#include <cstdio>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <cstdlib>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <thread>


int main() {
    const auto interface = getenv("INTERFACE");
    if (!interface) {
        perror("Interface env var is not set!");
        return 1;
    }

    const auto obj = bpf_object__open_file("./obj/kernel.o", nullptr);
    if (!obj) {
        perror("Failed to open bpf obj file!");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("Failed to load bpf object!");
        return 1;
    }

    const auto program = bpf_object__find_program_by_title(obj, "xdp");
    if (!program) {
        perror("Failed to find bpf program!");
        return 1;
    }

    const auto bpf_fd = bpf_program__fd(program);
    const auto interface_index = if_nametoindex(interface);
    if (interface_index == 0) {
        perror("Failed to find interface!");
        return 1;
    }


    std::cout << "Got index: " << interface_index << std::endl;

    if (bpf_set_link_xdp_fd(interface_index, bpf_fd, 0) < 0) {
        perror("Failed to attach xdp program to interface!");
        return 1;
    }

    std::cout << "Attached to XDP on " << interface << std::endl;

    const auto xdp_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xdp_fd < 0) {
        close(xdp_fd);
        perror("Can't create xdp socket!");
        return 1;
    }

    std::cout << "Created xdp socket: " << xdp_fd << std::endl;

    struct sockaddr_xdp address = {};
    memset(&address, 0, sizeof(address));
    address.sxdp_family = AF_XDP;
    address.sxdp_ifindex = interface_index;
    address.sxdp_queue_id = 63;
    address.sxdp_flags = (1 << 1);
// (1 << 1) XDP_FLAGS_SKB_MODE
// (1 << 2) XDP_FLAGS_DRV_MODE

    const auto bind_result = bind(xdp_fd, (struct sockaddr*) &address, sizeof(address));
    if (bind_result < 0) {
        close(xdp_fd);
        std::cerr << "Can't bind xdp socket to interface: " << bind_result << std::endl;
        return -1;
    }

    std::cout << "xdp socket has been binded: " << bind_result << std::endl;

    int i = 0;
    char packet[64];
    memset(packet, 0, sizeof(packet));

    while (++i < 30) {
        auto total_wrote = sizeof(packet);
        auto packet_ptr = packet;
        while (total_wrote != 0) {
            auto wrote = write(xdp_fd, packet_ptr, total_wrote);
            if (wrote < 0) {
                perror("Error writing to socket!");
                return (int) wrote;
            }

            packet_ptr += wrote;
            total_wrote -= wrote;
        }

        std::cout << "Wrote packet" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    close(xdp_fd);
    close(bpf_fd);

    std::cout << "Exiting program!" << std::endl;

    return 0;
}