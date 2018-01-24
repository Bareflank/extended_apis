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
    apic_intel_x64.cpp
    ept_entry_intel_x64.cpp
    ept_intel_x64.cpp
    root_ept_intel_x64.cpp
    vmcs_intel_x64_eapis_cr_access_hooks.cpp
    vmcs_intel_x64_eapis_cr.cpp
    vmcs_intel_x64_eapis_ept.cpp
    vmcs_intel_x64_eapis_event.cpp
    vmcs_intel_x64_eapis_io.cpp
    vmcs_intel_x64_eapis_isr_support_mock.cpp
    vmcs_intel_x64_eapis_isr_support.asm
    vmcs_intel_x64_eapis_isr.cpp
    vmcs_intel_x64_eapis_msr.cpp
    vmcs_intel_x64_eapis_vpid.cpp
    vmcs_intel_x64_eapis.cpp
    vmcs_intel_x64_vmm_state_eapis.cpp
)

add_shared_library(
    eapis_vmcs
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_VMCS
)

add_static_library(
    eapis_vmcs
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_VMCS
)
