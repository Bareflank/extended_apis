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

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    list(APPEND SOURCES
        arch/intel_x64/vmexit/control_register.cpp
        arch/intel_x64/vmexit/cpuid.cpp
        arch/intel_x64/vmexit/ept_misconfiguration.cpp
        arch/intel_x64/vmexit/ept_violation.cpp
        arch/intel_x64/vmexit/external_interrupt.cpp
        arch/intel_x64/vmexit/init_signal.cpp
        arch/intel_x64/vmexit/interrupt_window.cpp
        arch/intel_x64/vmexit/io_instruction.cpp
        arch/intel_x64/vmexit/monitor_trap.cpp
        arch/intel_x64/vmexit/mov_dr.cpp
        arch/intel_x64/vmexit/rdmsr.cpp
        arch/intel_x64/vmexit/sipi_signal.cpp
        arch/intel_x64/vmexit/wrmsr.cpp
        arch/intel_x64/vmexit/xsetbv.cpp
        arch/intel_x64/ept.cpp
        arch/intel_x64/microcode.cpp
        arch/intel_x64/mtrrs.cpp
        arch/intel_x64/vpid.cpp
        arch/intel_x64/apis.cpp
    )

elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()

add_shared_library(
    eapis_hve
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_HVE
    DEFINES SHARED_HVE
    DEFINES SHARED_MEMORY_MANAGER
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    eapis_hve
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_HVE
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)
