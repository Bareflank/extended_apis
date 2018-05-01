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
    DEFINES STATIC_DEBUG
)

do_test(test_page_table_entry
    SOURCES arch/intel_x64/ept/test_intrinsics.cpp
    ${ARGN}
)

do_test(test_memory_map
    SOURCES arch/intel_x64/ept/test_memory_map.cpp
    SOURCES arch/intel_x64/ept/ept_test_support.cpp
    CMD_LINE_ARGS ASAN_OPTIONS=detect_leaks=0
    ${ARGN}
)

do_test(test_ept_helpers
    SOURCES arch/intel_x64/ept/test_helpers.cpp
    SOURCES arch/intel_x64/ept/ept_test_support.cpp
    ${ARGN}
)

do_test(test_vpid
    SOURCES arch/intel_x64/test_vpid.cpp
    ${ARGN}
)

do_test(test_phys_x2apic
    SOURCES arch/intel_x64/test_phys_x2apic.cpp
    ${ARGN}
)

do_test(test_virt_x2apic
    SOURCES arch/intel_x64/test_virt_x2apic.cpp
    ${ARGN}
)

do_test(test_lapic_register
    SOURCES arch/intel_x64/test_lapic_register.cpp
    ${ARGN}
)

do_test(test_vic
    SOURCES arch/intel_x64/test_vic.cpp
    ${ARGN}
)

do_test(test_isr
    SOURCES arch/intel_x64/test_isr.cpp
    ${ARGN}
)

do_test(test_phys_pci
    SOURCES test_phys_pci.cpp
    ${ARGN}
)

do_test(test_pci_register
    SOURCES arch/x64/test_pci_register.cpp
    ${ARGN}
)

do_test(test_pci_device_allocator
    SOURCES test_pci_device_allocator.cpp
    ${ARGN}
)
