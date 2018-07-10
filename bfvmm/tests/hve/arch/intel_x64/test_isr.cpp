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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <intrinsics.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/isr.h>
#include <hve/arch/intel_x64/apic/vic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

std::unique_ptr<bfvmm::intel_x64::vmcs> g_vmcs{nullptr};
std::unique_ptr<bfvmm::intel_x64::exit_handler> g_ehlr{nullptr};

uint64_t reg[38] = {0};

TEST_CASE("default_isr")
{
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());

    reg[0] = reinterpret_cast<uint64_t>(&vic);
    vmcs_n::vm_entry_interruption_information::valid_bit::disable();

    close_interrupt_window();
    for (auto i = 32U; i < 256U; ++i) {
        default_isr(i, reg);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    }

    open_interrupt_window();
    for (auto i = 32U; i < 256U; ++i) {
        default_isr(i, reg);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
        CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == i);
    }
}

}
}

#endif
