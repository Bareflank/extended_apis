# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

link_directories(${CMAKE_INSTALL_PREFIX}/lib)

add_library(test_vmcs_support STATIC test_support.cpp)

macro(do_test str)
    add_executable(test_${str} test_${str}.cpp)
    target_compile_definitions(test_${str} PRIVATE STATIC_EAPIS_VMCS)
    target_compile_definitions(test_${str} PRIVATE STATIC_VMCS)
    target_compile_definitions(test_${str} PRIVATE STATIC_MEMORY_MANAGER)
    target_compile_definitions(test_${str} PRIVATE STATIC_INTRINSICS)
    target_link_libraries(test_${str} test_vmcs_support)
    target_link_libraries(test_${str} eapis_vmcs_static)
    target_link_libraries(test_${str} bfvmm_vmcs_static)
    target_link_libraries(test_${str} bfvmm_memory_manager_static)
    target_link_libraries(test_${str} bfvmm_intrinsics_static)
    target_link_libraries(test_${str} eapis_catch_static)
    add_test(test_${str} test_${str})
endmacro(do_test)

do_test(ept_entry_intel_x64)
do_test(ept_intel_x64)
do_test(root_ept_intel_x64)
do_test(vmcs_intel_x64_eapis)
do_test(vmcs_intel_x64_eapis_cr)
do_test(vmcs_intel_x64_eapis_ept)
do_test(vmcs_intel_x64_eapis_io)
do_test(vmcs_intel_x64_eapis_msr)
do_test(vmcs_intel_x64_eapis_vpid)
