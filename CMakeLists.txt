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

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/depends/capstone.cmake)

if(ENABLE_BUILD_VMM)
    vmm_extension(
        eapis
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    vmm_extension(
        eapis_main
        DEPENDS eapis
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )

    vmm_extension(
        eapis_integration
        DEPENDS eapis
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/
    )
endif()

if(ENABLE_BUILD_TEST)
    test_extension(
        eapis
        DEPENDS bfvmm
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/tests/
    )

    test_extension(
        eapis_bfsdk
        DEPENDS bfvmm
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfsdk/tests/
    )
endif()
