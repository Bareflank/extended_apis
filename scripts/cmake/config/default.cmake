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

include(${CMAKE_CURRENT_LIST_DIR}/../macros.cmake)

# ------------------------------------------------------------------------------
# Source Tree
# ------------------------------------------------------------------------------

set(EAPIS_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "Source root direfctory"
)

set(EAPIS_SOURCE_CMAKE_DIR ${CMAKE_CURRENT_LIST_DIR}/..
    CACHE INTERNAL
    "Cmake directory"
)

set(EAPIS_SOURCE_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}
    CACHE INTERNAL
    "Cmake configurations directory"
)

set(EAPIS_SOURCE_DEPENDS_DIR ${CMAKE_CURRENT_LIST_DIR}/../depends
    CACHE INTERNAL
    "Cmake dependencies directory"
)

set(EAPIS_SOURCE_BFVMM_DIR ${CMAKE_SOURCE_DIR}/../../../bfvmm
    CACHE INTERNAL
    "bfvmm source dir"
)

