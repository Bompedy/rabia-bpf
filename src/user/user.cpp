#include <cstdio>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <cstdlib>

int main() {
    const auto interface = getenv("INTERFACE");
    if (!interface) {
        perror("INTERFACE ENVIRONMENT VARIABLE NOT SET");
        return 1;
    }

    const auto obj = bpf_object__open_file("./obj/kernel.o", nullptr);
    if (!obj) {
        perror("FAILED TO OPEN BPF OBJ FILE");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("FAILED TO LOAD BPF OBJECT");
        return 1;
    }

    const auto program = bpf_object__find_program_by_title(obj, "xdp");
    if (!program) {
        perror("FAILED TO FIND BPF PROGRAM");
        return 1;
    }

    const auto fd = bpf_program__fd(program);
    const auto index = if_nametoindex(interface);
    if (index == 0) {
        perror("FAILED TO GET INTERFACE INDEX");
        return 1;
    }


    if (bpf_set_link_xdp_fd(index, fd, 0) <0) {
        perror("FAILED TO ATTACH XDP PROGRAM!");
        return 1;
    }

    printf("Attached to XDP on %s \n", interface);
    return 0;
}