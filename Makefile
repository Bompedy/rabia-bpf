INTERFACE = eth0
KERNEL_IN_FILE = src/kernel/kernel.c
KERNEL_OUT_FILE = obj/kernel.o
USER_IN_FILE = src/user/user.cpp
USER_OUT_FILE = obj/user

.PHONY: all clean

all: clean build

build:
	mkdir -p obj
	clang-15 -O2 -target bpf -c $(KERNEL_IN_FILE) -o $(KERNEL_OUT_FILE)
	clang-15 -o $(USER_OUT_FILE) $(USER_IN_FILE) -lbpf -lstdc++
	INTERFACE=$(INTERFACE) ./$(USER_OUT_FILE)

clean:
	rm -f $(KERNEL_OUT_FILE) $(USER_OUT_FILE)
	rm -rf obj

