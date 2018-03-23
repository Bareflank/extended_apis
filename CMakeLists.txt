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
# Includes
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/macros.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/targets.cmake)

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    vmm_extension(
        eapis
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    vmm_extension(
        eapis_main
        DEPENDS eapis
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )

    if(ENABLE_BUILD_INTEGRATION)
        add_integration(control_register)
        add_integration(cpuid)
        add_integration(io_instruction)
        add_integration(monitor_trap)
        add_integration(mov_dr)
        add_integration(rdmsr)
        add_integration(vpid)
        add_integration(wrmsr)
    endif()

endif()
