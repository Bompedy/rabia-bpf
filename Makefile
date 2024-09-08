INTERFACE = enp6s0f0
KERNEL_IN_FILE = src/kernel/kernel.c
KERNEL_OUT_FILE = obj/kernel.o
USER_SRC_DIR = src/user
USER_SRC_FILES = $(wildcard $(USER_SRC_DIR)/*.cpp)
#USER_IN_FILE = src/user/user.cpp
USER_OUT_FILE = obj/user

.PHONY: all clean build run

all: clean build run

build:
	mkdir -p obj
	clang-15 -O2 -target bpf -g -c $(KERNEL_IN_FILE) -o $(KERNEL_OUT_FILE)
	clang-15 -o $(USER_OUT_FILE) $(USER_SRC_FILES) -I$(USER_SRC_DIR) -lelf -lbpf -lstdc++ -lz

gen: build
	rm -f src/user/gen.h
	bpftool gen skeleton obj/kernel.o > src/user/gen.h

run:
	INTERFACE=$(INTERFACE) ./$(USER_OUT_FILE)

clean:
	sudo ip link set dev $(INTERFACE) xdp off
	rm -f $(KERNEL_OUT_FILE) $(USER_OUT_FILE)
	rm -rf obj

