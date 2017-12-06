cmake_minimum_required(VERSION 3.6)
project(eapis_test C CXX)
include(${BF_FLAGS_DIR}/flags.cmake)
include(CTest)
enable_testing(true)

enable_language(ASM_NASM)

# Temp hacks until we can restructure unit tests
set(BUILD_SYSROOT_VMM ${BUILD_SYSROOT_TEST})
set(BUILD_VMM_STATIC ON)
set(BUILD_VMM_SHARED OFF)

generate_flags(
    USERSPACE
    ADD_C_FLAGS "-DENABLE_UNITTESTING"
    ADD_CXX_FLAGS "-DENABLE_UNITTESTING"
    VERBOSE ${BUILD_VERBOSE}
)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../include
    ${BUILD_SYSROOT_OS}/include
    ${BUILD_SYSROOT_TEST}/include
)

link_directories(
    ${BUILD_SYSROOT_OS}/lib
    ${BUILD_SYSROOT_TEST}/lib
)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../src ${CMAKE_CURRENT_BINARY_DIR}/src)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../src/exit_handler/tests ${CMAKE_CURRENT_BINARY_DIR}/src/exit_handler/tests)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../src/misc/tests ${CMAKE_CURRENT_BINARY_DIR}/src/misc/tests)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../src/vmcs/tests ${CMAKE_CURRENT_BINARY_DIR}/src/vmcs/tests)
