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

function(add_integration INTEGRATION_DIR)
    set(TEST_SRC ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/arch/intel_x64/${INTEGRATION_DIR})

    if(NOT EXISTS "${TEST_SRC}")
        message(FATAL_ERROR "add_integration path not found: ${TEST_SRC}")
    endif()

    vmm_extension(
        eapis_integration_intel_x64_${INTEGRATION_DIR}
        DEPENDS eapis
        SOURCE_DIR ${TEST_SRC}
    )
endfunction(add_integration)
