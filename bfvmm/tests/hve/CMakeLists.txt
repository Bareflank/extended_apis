#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

list(APPEND ARGN
    DEPENDS eapis_hve
    DEPENDS bfvmm_hve
    DEPENDS bfvmm_vcpu
    DEPENDS bfvmm_memory_manager
)

do_test(test_helpers
    SOURCES arch/intel_x64/ept/test_helpers.cpp
    ${ARGN}
)

do_test(test_mmap
    SOURCES arch/intel_x64/ept/test_mmap.cpp
    ${ARGN}
)

do_test(test_ept
    SOURCES arch/intel_x64/test_ept.cpp
    ${ARGN}
)

do_test(test_mtrrs
    SOURCES arch/intel_x64/test_mtrrs.cpp
    ${ARGN}
)

do_test(test_vpid
    SOURCES arch/intel_x64/test_vpid.cpp
    ${ARGN}
)

do_test(test_control_register
    SOURCES arch/intel_x64/vmexit/test_control_register.cpp
    ${ARGN}
)

do_test(test_cpuid
    SOURCES arch/intel_x64/vmexit/test_cpuid.cpp
    ${ARGN}
)

do_test(test_ept_misconfiguration
    SOURCES arch/intel_x64/vmexit/test_ept_misconfiguration.cpp
    ${ARGN}
)

do_test(test_ept_violation
    SOURCES arch/intel_x64/vmexit/test_ept_violation.cpp
    ${ARGN}
)

# do_test(test_sipi
#     SOURCES arch/intel_x64/test_sipi.cpp
#     ${ARGN}
# )
do_test(test_external_interrupt
    SOURCES arch/intel_x64/vmexit/test_external_interrupt.cpp
    ${ARGN}
)

# do_test(test_init_signal
#     SOURCES arch/intel_x64/test_init_signal.cpp
#     ${ARGN}
# )

do_test(test_interrupt_window
    SOURCES arch/intel_x64/vmexit/test_interrupt_window.cpp
    ${ARGN}
)

# do_test(test_sipi
#     SOURCES arch/intel_x64/test_sipi.cpp
#     ${ARGN}
# )

# do_test(test_phys_ioapic
#     SOURCES arch/intel_x64/apic/test_phys_ioapic.cpp
#     ${ARGN}
# )

# do_test(test_phys_mtrr
#     SOURCES arch/intel_x64/test_phys_mtrr.cpp
#     ${ARGN}
# )

# do_test(test_virt_ioapic
#     SOURCES arch/intel_x64/apic/test_virt_ioapic.cpp
#     ${ARGN}
# )

# do_test(test_phys_x2apic
#     SOURCES arch/intel_x64/apic/test_phys_x2apic.cpp
#     ${ARGN}
# )

# do_test(test_virt_lapic
#     SOURCES arch/intel_x64/apic/test_virt_lapic.cpp
#     ${ARGN}
# )

# FIXME: when the rdmsr or wrmsr exit handler finds that the
# msr bitmap is null, it uses g_mm to allocate and translate
# This causes a map::at exception to be thrown, as right now the
# g_mm is bfignored in test_support.h
# do_test(test_vic
#     SOURCES arch/intel_x64/apic/test_vic.cpp
#     ${ARGN}
# )

# do_test(test_isr
#     SOURCES arch/intel_x64/test_isr.cpp
#     ${ARGN}
#     CMD_LINE_ARGS ASAN_OPTIONS=detect_leaks=0
# )

# do_test(test_esr
#     SOURCES arch/intel_x64/test_esr.cpp
#     ${ARGN}
# )

# do_test(test_phys_pci
#     SOURCES test_phys_pci.cpp
#     ${ARGN}
# )

# do_test(test_pci_register
#     SOURCES arch/x64/test_pci_register.cpp
#     ${ARGN}
# )

# do_test(test_pci_device_allocator
#     SOURCES test_pci_device_allocator.cpp
#     ${ARGN}
# )
