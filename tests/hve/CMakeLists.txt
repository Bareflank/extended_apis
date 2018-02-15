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

list(APPEND ARGN
    DEPENDS eapis_hve
    DEPENDS bfvmm_hve
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_EAPIS_HVE
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

do_test(test_exit_handler
    SOURCES arch/intel_x64/exit_handler/test_exit_handler.cpp
    ${ARGN}
)

do_test(test_ept
    SOURCES arch/intel_x64/ept/test_ept.cpp
    ${ARGN}
)

do_test(test_ept_entry
    SOURCES arch/intel_x64/ept/test_ept_entry.cpp
    ${ARGN}
)

do_test(test_root_ept
    SOURCES arch/intel_x64/ept/test_root_ept.cpp
    ${ARGN}
)

do_test(test_vmcs
    SOURCES arch/intel_x64/vmcs/test_vmcs.cpp
    ${ARGN}
)
