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
        arch/intel_x64/isr.cpp
    )

    if (NOT WIN32 AND NOT ENABLE_MOCKING)
        list(APPEND SOURCES
                arch/intel_x64/isr.asm
        )
    endif()

elseif(${BUILD_TARGET_ARCH} STREQUAL "aarch64")
    message(WARNING "Unimplemented")
else()
    message(FATAL_ERROR "Unsupported archiecture")
endif()

add_shared_library(
    eapis_vic
    SOURCES ${SOURCES}
    DEFINES SHARED_EAPIS_VIC
    DEFINES SHARED_VIC
    DEFINES SHARED_INTRINSICS
)

add_static_library(
    eapis_vic
    SOURCES ${SOURCES}
    DEFINES STATIC_EAPIS_VIC
    DEFINES STATIC_VIC
    DEFINES STATIC_INTRINSICS
)
