cmake_minimum_required(VERSION 3.6)
project(eapis C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)
enable_language(ASM_NASM)

generate_flags(
    VMM
    VERBOSE ${BUILD_VERBOSE}
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${BUILD_SYSROOT_VMM}/include/c++/v1
    ${BUILD_SYSROOT_VMM}/include
)

link_directories(
    ${BUILD_SYSROOT_VMM}/lib
)

add_subdirectory(src)

install(DIRECTORY include/exit_handler DESTINATION ${BUILD_SYSROOT_VMM}/include)
install(DIRECTORY include/vmcs DESTINATION ${BUILD_SYSROOT_VMM}/include)
install(FILES include/bitmanip_eapis.h DESTINATION ${BUILD_SYSROOT_VMM}/include)
