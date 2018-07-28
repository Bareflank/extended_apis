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

add_subdirectory(control_register)
add_subdirectory(cpuid)
add_subdirectory(efi)
#add_subdirectory(ept)
add_subdirectory(io_instruction)
add_subdirectory(monitor_trap)
add_subdirectory(mov_dr)
add_subdirectory(phys_pci)
add_subdirectory(rdmsr)
add_subdirectory(vic)
add_subdirectory(vpid)
add_subdirectory(wrmsr)
