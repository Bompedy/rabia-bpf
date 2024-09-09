cmake_minimum_required(VERSION 3.22)
project(bpf VERSION 1.0)

set(CMAKE_C_COMPILER "clang-15")
set(CMAKE_CXX_COMPILER "clang++-15")

#set(CMAKE_CXX_STANDARD 23)
#set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(src/kernel)
add_subdirectory(src/user)
add_dependencies(user kernel)
#target_link_libraries(user_app PRIVATE stdc++)