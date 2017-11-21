list(APPEND SOURCES
    apic_intel_x64.cpp
    ept_entry_intel_x64.cpp
    ept_intel_x64.cpp
    root_ept_intel_x64.cpp
    vmcs_intel_x64_eapis_cr.cpp
    vmcs_intel_x64_eapis_ept.cpp
    vmcs_intel_x64_eapis_event.cpp
    vmcs_intel_x64_eapis_io.cpp
    vmcs_intel_x64_eapis_isr.cpp
    vmcs_intel_x64_eapis_msr.cpp
    vmcs_intel_x64_eapis_vpid.cpp
    vmcs_intel_x64_eapis.cpp
    vmcs_intel_x64_vmm_state_eapis.cpp
)

if(NOT WIN32)
    list(APPEND SOURCES vmcs_intel_x64_eapis_isr_support.asm)
else()
    list(APPEND SOURCES vmcs_intel_x64_eapis_isr_support_mock.cpp)
endif()

if(BUILD_VMM_SHARED)
    add_library(eapis_vmcs_shared SHARED ${SOURCES})
    set_target_properties(eapis_vmcs_shared PROPERTIES OUTPUT_NAME "eapis_vmcs")
    target_compile_definitions(eapis_vmcs_shared PRIVATE SHARED_EAPIS_VMCS)
    target_link_libraries(eapis_vmcs_shared bfvmm_vmcs)
    target_link_libraries(eapis_vmcs_shared bfvmm_memory_manager)
    target_link_libraries(eapis_vmcs_shared bfvmm_intrinsics)
    install(TARGETS eapis_vmcs_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(eapis_vmcs_static STATIC ${SOURCES})
    set_target_properties(eapis_vmcs_static PROPERTIES OUTPUT_NAME "eapis_vmcs")
    target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_EAPIS_VMCS)
    target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_VMCS)
    target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_MEMORY_MANAGER)
    target_compile_definitions(eapis_vmcs_static PUBLIC STATIC_INTRINSICS)
    install(TARGETS eapis_vmcs_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
