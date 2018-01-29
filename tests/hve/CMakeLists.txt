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
    DEFINES STATIC_EAPIS_HVE
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

do_test(test_cpuid_emulation
    SOURCES arch/intel_x64/exit_handler/test_cpuid_emulation.cpp
    ${ARGN}
)

do_test(test_cpuid_vmcall
    SOURCES arch/intel_x64/exit_handler/test_cpuid_vmcall.cpp
    ${ARGN}
)

do_test(test_cr_emulation
    SOURCES arch/intel_x64/exit_handler/test_cr_emulation.cpp
    ${ARGN}
)

do_test(test_exit_handler
    SOURCES arch/intel_x64/exit_handler/test_exit_handler.cpp
    ${ARGN}
)

do_test(test_io_instruction_emulation
    SOURCES arch/intel_x64/exit_handler/test_io_instruction_emulation.cpp
    ${ARGN}
)

do_test(test_io_instruction_vmcall
    SOURCES arch/intel_x64/exit_handler/test_io_instruction_vmcall.cpp
    ${ARGN}
)

do_test(test_monitor_trap_emulation
    SOURCES arch/intel_x64/exit_handler/test_monitor_trap_emulation.cpp
    ${ARGN}
)

do_test(test_msr_vmcall
    SOURCES arch/intel_x64/exit_handler/test_msr_vmcall.cpp
    ${ARGN}
)

do_test(test_policy
    SOURCES arch/intel_x64/exit_handler/test_policy.cpp
    ${ARGN}
)

do_test(test_rdmsr_emulation
    SOURCES arch/intel_x64/exit_handler/test_rdmsr_emulation.cpp
    ${ARGN}
)

do_test(test_rdmsr_vmcall
    SOURCES arch/intel_x64/exit_handler/test_rdmsr_vmcall.cpp
    ${ARGN}
)

do_test(test_verifiers
    SOURCES arch/intel_x64/exit_handler/test_verifiers.cpp
    ${ARGN}
)

do_test(test_verifiers_vmcall
    SOURCES arch/intel_x64/exit_handler/test_verifiers_vmcall.cpp
    ${ARGN}
)

do_test(test_vpid_vmcall
    SOURCES arch/intel_x64/exit_handler/test_vpid_vmcall.cpp
    ${ARGN}
)

do_test(test_wrmsr_emulation
    SOURCES arch/intel_x64/exit_handler/test_wrmsr_emulation.cpp
    ${ARGN}
)

do_test(test_wrmsr_vmcall
    SOURCES arch/intel_x64/exit_handler/test_wrmsr_vmcall.cpp
    ${ARGN}
)

do_test(test_ept
    SOURCES arch/intel_x64/vmcs/test_ept.cpp
    ${ARGN}
)

do_test(test_ept_entry
    SOURCES arch/intel_x64/vmcs/test_ept_entry.cpp
    ${ARGN}
)

do_test(test_root_ept
    SOURCES arch/intel_x64/vmcs/test_root_ept.cpp
    ${ARGN}
)

do_test(test_vmcs
    SOURCES arch/intel_x64/vmcs/test_vmcs.cpp
    ${ARGN}
)

do_test(test_vmcs_cr
    SOURCES arch/intel_x64/vmcs/test_vmcs_cr.cpp
    ${ARGN}
)

do_test(test_vmcs_ept
    SOURCES arch/intel_x64/vmcs/test_vmcs_ept.cpp
    ${ARGN}
)

do_test(test_vmcs_io
    SOURCES arch/intel_x64/vmcs/test_vmcs_io.cpp
    ${ARGN}
)

do_test(test_vmcs_msr
    SOURCES arch/intel_x64/vmcs/test_vmcs_msr.cpp
    ${ARGN}
)

do_test(test_vmcs_vpid
    SOURCES arch/intel_x64/vmcs/test_vmcs_vpid.cpp
    ${ARGN}
)
