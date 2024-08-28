INTERFACE = eth0
KERNEL_IN_FILE = src/kernel/kernel.c
KERNEL_OUT_FILE = obj/kernel.o
USER_SRC_DIR = src/user
USER_SRC_FILES = $(wildcard $(USER_SRC_DIR)/*.cpp)
#USER_IN_FILE = src/user/user.cpp
USER_OUT_FILE = obj/user

.PHONY: all clean

all: clean build

build:
	mkdir -p obj
	clang-15 -O2 -target bpf -g -c $(KERNEL_IN_FILE) -o $(KERNEL_OUT_FILE)
	clang-15 -o $(USER_OUT_FILE) $(USER_SRC_FILES) -I/usr/include/nlohmann -lelf -lbpf -lstdc++ -lz
	INTERFACE=$(INTERFACE) ./$(USER_OUT_FILE)

clean:
	sudo ip link set dev $(INTERFACE) xdp off
	rm -f $(KERNEL_OUT_FILE) $(USER_OUT_FILE)
	rm -rf obj

