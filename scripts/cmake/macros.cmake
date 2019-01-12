#
# Bareflank Extended APIs
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
# eapis_vmm_extension
# ------------------------------------------------------------------------------

function(eapis_add_vmm_executable NAME)
    list(APPEND ARGN
        LIBRARIES eapis_hve
        EXT_LIBRARIES udis86
    )

    add_vmm_executable(
        ${NAME}
        ${ARGN}
    )
endfunction(eapis_add_vmm_executable)

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

function(eapis_vmm_extension NAME)
    list(APPEND ARGN
        DEPENDS eapis_bfvmm
    )

    vmm_extension(
        ${NAME}
        ${ARGN}
    )
endfunction(eapis_vmm_extension)
