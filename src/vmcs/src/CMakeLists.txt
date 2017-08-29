# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    apic_intel_x64.cpp
    ept_entry_intel_x64.cpp
    ept_intel_x64.cpp
    root_ept_intel_x64.cpp
    vmcs_intel_x64_eapis.cpp
    vmcs_intel_x64_eapis_cr.cpp
    vmcs_intel_x64_eapis_ept.cpp
    vmcs_intel_x64_eapis_event.cpp
    vmcs_intel_x64_eapis_io.cpp
    vmcs_intel_x64_eapis_msr.cpp
    vmcs_intel_x64_eapis_vpid.cpp
    vmcs_intel_x64_vmm_state_eapis.cpp
)

link_directories(${CMAKE_INSTALL_PREFIX}/lib)

add_library(eapis_vmcs SHARED ${SOURCES})
add_library(eapis_vmcs_static STATIC ${SOURCES})

target_compile_definitions(eapis_vmcs PRIVATE SHARED_EAPIS_VMCS)
target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_EAPIS_VMCS)
target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_VMCS)
target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(eapis_vmcs bfvmm_vmcs)
target_link_libraries(eapis_vmcs bfvmm_memory_manager)
target_link_libraries(eapis_vmcs bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS eapis_vmcs DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS eapis_vmcs_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
