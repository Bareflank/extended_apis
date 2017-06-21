# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include(${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

list(APPEND SOURCES
    vcpu_factory_intel_x64_eapis.cpp
)

add_library(eapis_vcpu_factory SHARED ${SOURCES})
add_library(eapis_vcpu_factory_static STATIC ${SOURCES})

target_compile_definitions(eapis_vcpu_factory PRIVATE SHARED_VCPU)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_VCPU)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_DEBUG_RING)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_INTRINSICS)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_MEMORY_MANAGER)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_VMXON)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_VMCS)
target_compile_definitions(eapis_vcpu_factory_static PUBLIC STATIC_EXIT_HANDLER)

target_link_libraries(eapis_vcpu_factory bfvmm_vcpu)
target_link_libraries(eapis_vcpu_factory bfvmm_vmxon)
target_link_libraries(eapis_vcpu_factory bfvmm_exit_handler)
target_link_libraries(eapis_vcpu_factory bfvmm_vmcs)
target_link_libraries(eapis_vcpu_factory bfvmm_memory_manager)
target_link_libraries(eapis_vcpu_factory bfvmm_debug_ring)
target_link_libraries(eapis_vcpu_factory bfvmm_intrinsics)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

if(CMAKE_TOOLCHAIN_FILE)
    install(TARGETS eapis_vcpu_factory DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
    install(TARGETS eapis_vcpu_factory_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
else()
    install(TARGETS eapis_vcpu_factory DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS eapis_vcpu_factory_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
endif()
