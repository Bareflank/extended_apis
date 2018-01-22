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
    vcpu_factory_intel_x64.cpp
)

set(ARG_LIBRARIES "")
if(BUILD_SHARED_LIBS)
    list(APPEND ARG_LIBRARIES
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_exit_handler_shared.so
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_vmcall_policy_shared.so
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_vmcs_shared.so
    )
endif()

if(BUILD_STATIC_LIBS)
    list(APPEND ARG_LIBRARIES
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_exit_handler_shared.a
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_vmcall_policy_shared.a
        ${CMAKE_INSTALL_PREFIX}/lib/libeapis_vmcs_shared.a
    )
endif()

add_vmm_executable(eapis_vcpu_factory
    SOURCES ${SOURCES}
    LIBRARIES ${ARG_LIBRARIES}
)
