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

if(${BUILD_TARGET_ARCH} STREQUAL "x86_64")
    if(NOT ENABLE_MOCKING)
        list(APPEND SOURCES
            arch/intel_x64/vmcall_policy.cpp
        )
    endif()
elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_shared_library(
    eapis_policy
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_VMCALL_POLICY
    DEFINES SHARED_EAPIS_HVE
)

add_static_library(
    eapis_policy
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_VMCALL_POLICY
    DEFINES STATIC_EAPIS_HVE
)
