# Path to the BPF kernel source file
set(KERNEL_SRC_FILE ${CMAKE_SOURCE_DIR}/src/kernel/kernel.c)

# Path to the output BPF kernel object file
set(KERNEL_OBJ_FILE ${CMAKE_BINARY_DIR}/obj/kernel.o)

# Path to the generated skeleton file
set(SKELETON_FILE ${CMAKE_SOURCE_DIR}/src/user/gen.h)

# Ensure the output directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/obj)

# Custom command to build the BPF kernel object
add_custom_command(
        OUTPUT ${KERNEL_OBJ_FILE}
        COMMAND clang-15 -O2 -target bpf -g -c ${KERNEL_SRC_FILE} -o ${KERNEL_OBJ_FILE}
        DEPENDS ${KERNEL_SRC_FILE}
        COMMENT "Building BPF kernel object"
)

# Custom command to generate the skeleton file
add_custom_command(
        OUTPUT ${SKELETON_FILE}
        COMMAND bpftool gen skeleton ${KERNEL_OBJ_FILE} > ${SKELETON_FILE}
        DEPENDS ${KERNEL_OBJ_FILE}
        COMMENT "Generating BPF skeleton file"
)

# Custom target to build the kernel object and generate the skeleton file
add_custom_target(
        kernel ALL
        DEPENDS ${KERNEL_OBJ_FILE} ${SKELETON_FILE}
)
