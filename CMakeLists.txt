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

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)

# ------------------------------------------------------------------------------
# Project File
# ------------------------------------------------------------------------------

add_project_include(${EAPIS_SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# General Dependencies
# ------------------------------------------------------------------------------

include_dependency(EAPIS_SOURCE_DEPENDS_DIR capstone)

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    add_subproject(
        eapis_bfvmm vmm
        DEPENDS bfvmm
        DEPENDS bfintrinsics
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    add_subproject(
        eapis_bfvmm_main vmm
        DEPENDS eapis_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )

    add_subproject(
        eapis_integration vmm
        DEPENDS eapis_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_TEST)
    add_subproject(
        eapis_bfvmm test
        DEPENDS bfvmm
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/tests/
    )

    add_subproject(
        eapis_bfsdk test
        DEPENDS bfvmm
        DEPENDS capstone
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfsdk/tests/
    )
endif()
