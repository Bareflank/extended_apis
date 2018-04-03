//
// Bareflank Extended APIs
//
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <algorithm>
#include <intrinsics.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/vic.h>
#include <hve/arch/intel_x64/isr.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;
namespace lapic_n = ::intel_x64::lapic;
namespace proc_ctls1 = vmcs_n::primary_processor_based_vm_execution_controls;
namespace proc_ctls2 = vmcs_n::secondary_processor_based_vm_execution_controls;

std::unique_ptr<bfvmm::intel_x64::vmcs> g_vmcs{nullptr};
std::unique_ptr<bfvmm::intel_x64::exit_handler> g_ehlr{nullptr};

uint64_t reg[38] = {0};

TEST_CASE("isr: vector_to_str")
{
    CHECK(strcmp(vector_to_str(0x00U), "fault: divide by 0") == 0);
    CHECK(strcmp(vector_to_str(0x01U), "fault/trap: debug exception") == 0);
    CHECK(strcmp(vector_to_str(0x02U), "interrupt: nmi") == 0);
    CHECK(strcmp(vector_to_str(0x03U), "trap: breakpoint") == 0);
    CHECK(strcmp(vector_to_str(0x04U), "trap: overflow") == 0);
    CHECK(strcmp(vector_to_str(0x05U), "fault: bound range exceeded") == 0);
    CHECK(strcmp(vector_to_str(0x06U), "fault: invalid opcode") == 0);
    CHECK(strcmp(vector_to_str(0x07U), "fault: device not available (no math coprocessor") == 0);
    CHECK(strcmp(vector_to_str(0x08U), "abort: double fault") == 0);
    CHECK(strcmp(vector_to_str(0x09U), "fault: coprocessor segment overrun") == 0);
    CHECK(strcmp(vector_to_str(0x0AU), "fault: invalid TSS") == 0);
    CHECK(strcmp(vector_to_str(0x0BU), "fault: segment not present") == 0);
    CHECK(strcmp(vector_to_str(0x0CU), "fault: stack segment fault") == 0);
    CHECK(strcmp(vector_to_str(0x0DU), "fault: general protection fault") == 0);
    CHECK(strcmp(vector_to_str(0x0EU), "fault: page fault") == 0);
    CHECK(strcmp(vector_to_str(0x10U), "fault: x87 fpu floating point error") == 0);
    CHECK(strcmp(vector_to_str(0x11U), "fault: alignment check") == 0);
    CHECK(strcmp(vector_to_str(0x12U), "abort: machine check") == 0);
    CHECK(strcmp(vector_to_str(0x13U), "fault: simd floating point exception") == 0);
    CHECK(strcmp(vector_to_str(0x14U), "fault: virtualization exception") == 0);
    CHECK(strcmp(vector_to_str(0x16U), "undefined") == 0);
}

TEST_CASE("isr: default_isr - interrupt")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic(hve.get());

    reg[0] = reinterpret_cast<uint64_t>(&vic);
    vmcs_n::vm_entry_interruption_information::valid_bit::disable();

    close_interrupt_window();
    for (auto i = 32U; i < 256U; ++i) {
        default_isr(i, 0, 0, reg);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    }

    open_interrupt_window();
    for (auto i = 32U; i < 256U; ++i) {
        default_isr(i, 0, 0, reg);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
        CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == i);
    }
}

TEST_CASE("isr: default_isr - exception")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic(hve.get());

    reg[0] = reinterpret_cast<uint64_t>(&vic);
    vmcs_n::vm_entry_interruption_information::valid_bit::disable();
    g_cr2 = 0U;
    auto ec = 0U;
    auto ec_valid = true;

    for (auto i = 0U; i < 32U; ++i) {
        default_isr(i, ec, ec_valid, reg);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    }
}

}
}

#endif
