# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Custom Flags
# ------------------------------------------------------------------------------

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(NOT EXISTS ${CMAKE_BINARY_DIR}/null.cpp)
    file(WRITE
        ${CMAKE_BINARY_DIR}/null.cpp ""
    )
endif()

add_executable(eapis ${CMAKE_BINARY_DIR}/null.cpp)

target_link_libraries(eapis bfvmm_vcpu)
target_link_libraries(eapis eapis_vcpu_factory)
target_link_libraries(eapis bfvmm_vcpu_manager)
target_link_libraries(eapis bfvmm_debug_ring)
target_link_libraries(eapis eapis_exit_handler)
target_link_libraries(eapis bfvmm_exit_handler)
target_link_libraries(eapis eapis_vmcs)
target_link_libraries(eapis bfvmm_vmcs)
target_link_libraries(eapis bfvmm_vmxon)
target_link_libraries(eapis bfvmm_serial)
target_link_libraries(eapis bfvmm_memory_manager)
target_link_libraries(eapis bfvmm_intrinsics)
target_link_libraries(eapis -Wl,--whole-archive bfvmm_main_static -Wl,--no-whole-archive)

if(CMAKE_TOOLCHAIN_FILE)
    target_link_libraries(eapis bfvmm_support)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS eapis DESTINATION ${BAREFLANK_SYSROOT_PATH}/bin)
else()
    install(TARGETS eapis DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
