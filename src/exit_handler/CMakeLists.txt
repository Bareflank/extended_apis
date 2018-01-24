#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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
    exit_handler_intel_x64_eapis_cpuid_emulation.cpp
    exit_handler_intel_x64_eapis_cpuid_vmcall.cpp
    exit_handler_intel_x64_eapis_cr_access_hooks.cpp
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
    exit_handler_intel_x64_eapis_verifiers_vmcall.cpp
    exit_handler_intel_x64_eapis_verifiers.cpp
    exit_handler_intel_x64_eapis_vpid_vmcall.cpp
    exit_handler_intel_x64_eapis_wrmsr_emulation.cpp
    exit_handler_intel_x64_eapis_wrmsr_vmcall.cpp
    exit_handler_intel_x64_eapis.cpp
)

add_shared_library(
    eapis_exit_handler
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_EXIT_HANDLER
)

add_static_library(
    eapis_exit_handler
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_EXIT_HANDLER
)
