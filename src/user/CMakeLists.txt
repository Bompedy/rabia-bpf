# Ensure the output directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/obj)

# User-space source files
file(GLOB USER_SRC_FILES ${CMAKE_SOURCE_DIR}/src/user/*.cpp)

# Set the output path for user-space executable
set(USER_EXECUTABLE ${CMAKE_BINARY_DIR}/obj/user)

# Create the user-space executable
add_executable(user ${USER_SRC_FILES} ${CMAKE_SOURCE_DIR}/src/kernel/kernel.c)
target_include_directories(user PRIVATE ${CMAKE_SOURCE_DIR}/src/user)
target_link_libraries(user PRIVATE elf bpf stdc++ z)

# Set runtime output directory
set_target_properties(user PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/obj)

message(STATUS "INTERFACE environment variable: $ENV{INTERFACE}")
# Custom command to run the user-space application
add_custom_target(
        run
        COMMAND ${CMAKE_COMMAND} -E env INTERFACE=$ENV{INTERFACE} ${USER_EXECUTABLE} --interface $ENV{INTERFACE}
        DEPENDS user
        COMMENT "Running user-space application"
)
# Ensure user depends on kernel object generation
#add_dependencies(user kernel)