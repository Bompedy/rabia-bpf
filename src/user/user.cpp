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


std::string getMachineIpAddress() {
    std::string ipAddress;
    struct ifaddrs *ifAddrStruct = nullptr;
    struct ifaddrs *ifa = nullptr;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifAddrStruct) == -1) {
        throw std::runtime_error("Failed to get network interfaces");
    }

    for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (getnameinfo(ifa->ifa_addr, sizeof(sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST) == 0) {
                if (std::string(host) != "127.0.0.1") {
                    ipAddress = host;
                }
            }
        }
    }

    freeifaddrs(ifAddrStruct);
    return ipAddress.empty() ? "No valid IP found" : ipAddress;
}

std::vector<std::string> getPodIps(const std::string& build_time) {
    std::vector<std::string> matchingIPs;
    std::string command = "curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" "
                          "--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt "
                          "https://kubernetes.default.svc/api/v1/namespaces/default/pods";
    std::array<char, 128> buffer{};
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) result += buffer.data();


    try {
        auto j = nlohmann::json::parse(result);
        auto items = j["items"];

        for (const auto& item : items) {
            std::string podBuildTime = item["metadata"]["labels"]["build-time"];
            std::string podIP = item["status"]["podIP"];

            if (podBuildTime == build_time) {
                matchingIPs.push_back(podIP);
            }
        }
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
    }

    return matchingIPs;
}

int main() {

    const auto build_time = getenv("BUILD_TIME"); // KUBERNETES
    const auto machine_address = getMachineIpAddress();
    std::vector<std::string> pod_addresses;
    if (build_time) {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // give time for others to start
        pod_addresses = getPodIps(build_time);
    } else {
        pod_addresses = {
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3"
        };
    }

    if (pod_addresses.empty()) {
        std::cout << "Can't find any ips!" << std::endl;
        return EXIT_FAILURE;
    }

    for (const auto& ip : pod_addresses) {
        std::cout << "Pod IP: " << ip << std::endl;
    }

    const auto interface = getenv("INTERFACE");
    if (!interface) {
        std::cerr << "Interface env var is not set!" << std::endl;
        return EXIT_FAILURE;
    }
    char command[256];
    snprintf(command, sizeof(command),"tc qdisc add dev %s clsact", interface);
    if (system(command) != 0) {
        fprintf(stderr, "Failed to execute command: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    printf("Successfully added qdisc to %s\n", interface);

    const auto obj = bpf_object__open_file("./obj/kernel.o", nullptr);
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

    const auto tc_program = bpf_object__find_program_by_name(obj, "tc_hook");
    if (!tc_program) {
        std::cerr << "Failed to find TC program: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    const auto tc_fd = bpf_program__fd(tc_program);

    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    hook.sz = sizeof(hook);
    hook.attach_point = BPF_TC_EGRESS;
    hook.ifindex = interface_index;
    opts.sz = sizeof(opts);
    opts.prog_fd = tc_fd;

    if (bpf_tc_attach(&hook, &opts)) {
        std::cerr << "Failed to attach TC program to interface: " << std::strerror(errno) << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Attached to tc!" << std::endl;


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

    char packet[64];
    memset(packet, 0, sizeof(packet));

    while (true) {
        if (write(fd, packet, sizeof(packet)) < 0) {
            std::cerr << "Error sending packet: " << std::strerror(errno) << std::endl;
        } else {
            std::cout << "64-byte packet sent" << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    close(fd);
    close(bpf_fd);
    std::cout << "Exiting program!" << std::endl;
    return 0;
}
