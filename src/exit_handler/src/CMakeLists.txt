# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

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
)

if(BUILD_SHARED_LIBS)
    add_library(eapis_exit_handler SHARED ${SOURCES})
    target_compile_definitions(eapis_exit_handler PRIVATE SHARED_EAPIS_EXIT_HANDLER)
    target_link_libraries(eapis_exit_handler bfvmm_exit_handler)
    target_link_libraries(eapis_exit_handler eapis_vmcs)
    target_link_libraries(eapis_exit_handler bfvmm_vmcs)
    target_link_libraries(eapis_exit_handler bfvmm_memory_manager)
    target_link_libraries(eapis_exit_handler bfvmm_intrinsics)
endif()

if(BUILD_STATIC_LIBS)
    add_library(eapis_exit_handler STATIC ${SOURCES})
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_EAPIS_EXIT_HANDLER)
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_EXIT_HANDLER)
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_EAPIS_VMCS)
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_VMCS)
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_MEMORY_MANAGER)
    target_compile_definitions(eapis_exit_handler PRIVATE STATIC_INTRINSICS)
endif()

if(NOT CMAKE_TOOLCHAIN_FILE)
    target_compile_definitions(eapis_exit_handler PRIVATE SHOW_VMCALLS)
endif()

install(TARGETS eapis_exit_handler DESTINATION ${INSTALL_LIB_DIR})
