list(APPEND SOURCES
    exit_handler_intel_x64_eapis.cpp
    exit_handler_intel_x64_eapis_cr_emulation.cpp
    exit_handler_intel_x64_eapis_event_emulation.cpp
    exit_handler_intel_x64_eapis_event_vmcall.cpp
    exit_handler_intel_x64_eapis_io_instruction_emulation.cpp
    exit_handler_intel_x64_eapis_io_instruction_vmcall.cpp
    exit_handler_intel_x64_eapis_monitor_trap_emulation.cpp
    exit_handler_intel_x64_eapis_msr_vmcall.cpp
    exit_handler_intel_x64_eapis_policy.cpp
    exit_handler_intel_x64_eapis_rdmsr_emulation.cpp
    exit_handler_intel_x64_eapis_rdmsr_vmcall.cpp
    exit_handler_intel_x64_eapis_verifiers.cpp
    exit_handler_intel_x64_eapis_verifiers_vmcall.cpp
    exit_handler_intel_x64_eapis_vpid_vmcall.cpp
    exit_handler_intel_x64_eapis_wrmsr_emulation.cpp
    exit_handler_intel_x64_eapis_wrmsr_vmcall.cpp
    exit_handler_intel_x64_eapis_cpuid_emulation.cpp
    exit_handler_intel_x64_eapis_cpuid_vmcall.cpp
)

if(BUILD_VMM_SHARED)
    add_library(eapis_exit_handler_shared SHARED ${SOURCES})
    set_target_properties(eapis_exit_handler_shared PROPERTIES OUTPUT_NAME "eapis_exit_handler")
    target_compile_definitions(eapis_exit_handler_shared PRIVATE SHARED_EAPIS_EXIT_HANDLER)
    if(${PROJECT_NAME} STREQUAL "eapis_test")
        target_compile_definitions(eapis_exit_handler_shared PRIVATE SHOW_VMCALLS)
    endif()
    target_link_libraries(eapis_exit_handler_shared bfvmm_exit_handler)
    target_link_libraries(eapis_exit_handler_shared eapis_vmcs_shared)
    target_link_libraries(eapis_exit_handler_shared bfvmm_vmcs)
    target_link_libraries(eapis_exit_handler_shared bfvmm_memory_manager)
    target_link_libraries(eapis_exit_handler_shared bfvmm_intrinsics)
    install(TARGETS eapis_exit_handler_shared DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()

if(BUILD_VMM_STATIC)
    add_library(eapis_exit_handler_static STATIC ${SOURCES})
    set_target_properties(eapis_exit_handler_static PROPERTIES OUTPUT_NAME "eapis_exit_handler")
    if(${PROJECT_NAME} STREQUAL "eapis_test")
        target_compile_definitions(eapis_exit_handler_static PRIVATE SHOW_VMCALLS)
    endif()
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_EAPIS_EXIT_HANDLER)
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_EXIT_HANDLER)
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_EAPIS_VMCS)
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_VMCS)
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_MEMORY_MANAGER)
    target_compile_definitions(eapis_exit_handler_static PRIVATE STATIC_INTRINSICS)
    install(TARGETS eapis_exit_handler_static DESTINATION ${BUILD_SYSROOT_VMM}/lib)
endif()
