INTERFACE = enp65s0f0np0
KERNEL_IN_FILE = src/kernel/kernel.c
KERNEL_OUT_FILE = obj/kernel.o
USER_IN_FILE = src/user/user.cpp
USER_OUT_FILE = obj/user

link-types:
	ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

check-xdp:
	bpftool net show dev $(INTERFACE)

disable-xdp:
	ip link set dev $(INTERFACE) xdp off

build-xdp:
	mkdir -p obj
	clang-15 -O2 -target bpf -c $(KERNEL_IN_FILE) -o $(KERNEL_OUT_FILE)

clean-xdp:
	rm -f $(KERNEL_OUT_FILE)

deploy-xdp: clean-xdp build-xdp
	ip link set dev $(INTERFACE) xdp off
	ip link set dev $(INTERFACE) xdp obj $(KERNEL_OUT_FILE) sec xdp

build-user: clean-user
	mkdir -p obj
	clang-15 -o $(USER_OUT_FILE) $(USER_IN_FILE) -lbpf -lstdc++

deploy-user: clean-user build-user
	INTERFACE=$(INTERFACE) ./$(USER_OUT_FILE)

clean-user:
	rm -f $(USER_OUT_FILE)

clean: clean-xdp clean-user

all: disable-xdp build-xdp deploy-user

.PHONY: check-xdp disable-xdp build-xdp clean-xdp deploy-xdp build-user deploy-user clean-user clean all

