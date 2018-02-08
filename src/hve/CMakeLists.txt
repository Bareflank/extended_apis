#
# Bareflank Hypervisor
# Copyright (C) 2018 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

list(APPEND SOURCES
    arch/intel_x64/ept/ept.cpp
    arch/intel_x64/ept/ept_entry.cpp
    arch/intel_x64/ept/root_ept.cpp

    arch/intel_x64/exit_handler/cpuid_emulation.cpp
    arch/intel_x64/exit_handler/cpuid_vmcall.cpp
    arch/intel_x64/exit_handler/cr_emulation.cpp
    arch/intel_x64/exit_handler/event_emulation.cpp
    arch/intel_x64/exit_handler/event_vmcall.cpp
    arch/intel_x64/exit_handler/exit_handler.cpp
    arch/intel_x64/exit_handler/io_instruction_emulation.cpp
    arch/intel_x64/exit_handler/io_instruction_vmcall.cpp
    arch/intel_x64/exit_handler/monitor_trap_emulation.cpp
    arch/intel_x64/exit_handler/msr_vmcall.cpp
    arch/intel_x64/exit_handler/policy.cpp
    arch/intel_x64/exit_handler/rdmsr_emulation.cpp
    arch/intel_x64/exit_handler/rdmsr_vmcall.cpp
    arch/intel_x64/exit_handler/verifiers.cpp
    arch/intel_x64/exit_handler/verifiers_vmcall.cpp
    arch/intel_x64/exit_handler/vpid_vmcall.cpp
    arch/intel_x64/exit_handler/wrmsr_emulation.cpp
    arch/intel_x64/exit_handler/wrmsr_vmcall.cpp

    arch/intel_x64/vmcs/vmcs.cpp
    arch/intel_x64/vmcs/vmcs_cr_access_hooks.cpp
    arch/intel_x64/vmcs/vmcs_ept.cpp
    arch/intel_x64/vmcs/vmcs_event.cpp
    arch/intel_x64/vmcs/vmcs_io.cpp
    arch/intel_x64/vmcs/vmcs_isr.cpp
    arch/intel_x64/vmcs/vmcs_msr.cpp
    arch/intel_x64/vmcs/vmcs_vmm_state.cpp
    arch/intel_x64/vmcs/vmcs_vpid.cpp
)

if(ENABLE_MOCKING)
    list(APPEND SOURCES
        arch/intel_x64/vmcs/vmcs_isr_support_mock.cpp
    )
elseif(NOT WIN32)
    list(APPEND SOURCES
        arch/intel_x64/vmcs/vmcs_isr_support.asm
    )
endif()

add_shared_library(
    eapis_hve
    DEPENDS bfvmm_hve
    DEPENDS bfvmm_memory_manager
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_HVE
    DEFINES SHARED_HVE
    DEFINES SHARED_MEMORY_MANAGER
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    eapis_hve
    DEPENDS bfvmm_hve
    DEPENDS bfvmm_memory_manager
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_HVE
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)
