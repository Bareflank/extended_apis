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
        arch/intel_x64/control_register.cpp
        arch/intel_x64/cpuid.cpp
        arch/intel_x64/external_interrupt.cpp
        arch/intel_x64/io_instruction.cpp
        arch/intel_x64/monitor_trap.cpp
        arch/intel_x64/mov_dr.cpp
        arch/intel_x64/rdmsr.cpp
        arch/intel_x64/vpid.cpp
        arch/intel_x64/wrmsr.cpp
        arch/intel_x64/hve.cpp
    )
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
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
