# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHOW_VMCALLS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHOW_VMCALLS")
endif()

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
    exit_handler_intel_x64_eapis_isr.cpp
    exit_handler_intel_x64_eapis_isr_support.asm
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

link_directories(${CMAKE_INSTALL_PREFIX}/lib)

add_library(eapis_exit_handler SHARED ${SOURCES})
add_library(eapis_exit_handler_static STATIC ${SOURCES})

target_compile_definitions(eapis_exit_handler PRIVATE SHARED_EAPIS_EXIT_HANDLER)
target_compile_definitions(eapis_exit_handler_static PUBLIC STATIC_EAPIS_EXIT_HANDLER)
target_compile_definitions(eapis_exit_handler_static PUBLIC STATIC_EAPIS_VMCS)
target_compile_definitions(eapis_exit_handler_static PUBLIC STATIC_VMCS)
target_compile_definitions(eapis_exit_handler_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(eapis_exit_handler_static PUBLIC STATIC_INTRINSICS)

target_link_libraries(eapis_exit_handler bfvmm_exit_handler)
target_link_libraries(eapis_exit_handler eapis_vmcs)
target_link_libraries(eapis_exit_handler bfvmm_vmcs)
target_link_libraries(eapis_exit_handler bfvmm_memory_manager)
target_link_libraries(eapis_exit_handler bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS eapis_exit_handler DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS eapis_exit_handler_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
endif()
