# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSHOW_VMCALLS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSHOW_VMCALLS")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

link_directories(${CMAKE_INSTALL_PREFIX}/lib)

add_library(test_exit_handler_support STATIC test_support.cpp)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_EAPIS_EXIT_HANDLER)
    target_compile_definitions(test_${str} PRIVATE STATIC_EXIT_HANDLER)
    target_compile_definitions(test_${str} PRIVATE STATIC_EAPIS_VMCS)
    target_compile_definitions(test_${str} PRIVATE STATIC_VMCS)
    target_compile_definitions(test_${str} PRIVATE STATIC_MEMORY_MANAGER)
    target_compile_definitions(test_${str} PRIVATE STATIC_INTRINSICS)
    target_link_libraries(test_${str} test_exit_handler_support)
    target_link_libraries(test_${str} eapis_exit_handler_static)
    target_link_libraries(test_${str} bfvmm_exit_handler_static)
    target_link_libraries(test_${str} eapis_vmcs_static)
    target_link_libraries(test_${str} bfvmm_vmcs_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} eapis_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(exit_handler_intel_x64_eapis)
do_test(exit_handler_intel_x64_eapis_cr_emulation)
do_test(exit_handler_intel_x64_eapis_io_instruction_emulation)
do_test(exit_handler_intel_x64_eapis_io_instruction_vmcall)
do_test(exit_handler_intel_x64_eapis_monitor_trap_emulation)
do_test(exit_handler_intel_x64_eapis_msr_vmcall)
do_test(exit_handler_intel_x64_eapis_policy)
do_test(exit_handler_intel_x64_eapis_rdmsr_emulation)
do_test(exit_handler_intel_x64_eapis_rdmsr_vmcall)
do_test(exit_handler_intel_x64_eapis_verifiers)
do_test(exit_handler_intel_x64_eapis_verifiers_vmcall)
do_test(exit_handler_intel_x64_eapis_vpid_vmcall)
do_test(exit_handler_intel_x64_eapis_wrmsr_emulation)
do_test(exit_handler_intel_x64_eapis_wrmsr_vmcall)
