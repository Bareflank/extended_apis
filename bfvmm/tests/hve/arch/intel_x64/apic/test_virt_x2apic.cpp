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
#include <hve/arch/intel_x64/apic/virt_x2apic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;
namespace lapic_n = ::intel_x64::lapic;
namespace proc_ctls1 = vmcs_n::primary_processor_based_vm_execution_controls;

std::unique_ptr<bfvmm::intel_x64::vmcs> g_vmcs{nullptr};
std::unique_ptr<bfvmm::intel_x64::exit_handler> g_ehlr{nullptr};

TEST_CASE("virt_x2apic::virt_x2apic(hve, phys_x2apic)")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();

    CHECK_NOTHROW(eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get()));
}

TEST_CASE("virt_x2apic: tpr")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto addr = msrs_n::ia32_x2apic_tpr::addr;

    vapic.write_register(addr, 0xFFFFFFFFU);
    CHECK(vapic.read_tpr() == 0xFFFFFFFFU);

    vapic.write_tpr(0xDEADU);
    CHECK(vapic.read_tpr() == 0xDEADU);
}

TEST_CASE("virt_x2apic: icr")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto addr = msrs_n::ia32_x2apic_icr::addr;

    vapic.write_register(addr, 0xF00DU);
    CHECK(vapic.read_register(addr) == 0xF00DU);
}

TEST_CASE("virt_x2apic: self_ipi")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());

    vapic.write_self_ipi(0xFEU);
    CHECK(vapic.read_register(msrs_n::ia32_x2apic_self_ipi::addr) == 0xFEU);
}

TEST_CASE("virt_x2apic: svr")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto addr = msrs_n::ia32_x2apic_svr::addr;

    vapic.write_register(addr, 0xFFFFFFFFU);
    CHECK(vapic.read_svr() == 0xFFFFFFFFU);

    vapic.write_svr(0xDEADU);
    CHECK(vapic.read_svr() == 0xDEADU);
}

TEST_CASE("virt_x2apic: queue_injection - window closed - rflags.if")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto vec = 100U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_x2apic: queue_injection - window closed - blocking by sti")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto vec = 32U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_interruptibility_state::blocking_by_sti::enable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_x2apic: queue_injection - window closed - blocking by mov ss")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto vec = 42U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::enable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_x2apic: queue_injection - window open")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto vec = 99U;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();
    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::disable();
    vapic.queue_injection(vec);

    CHECK(vapic.irr_is_empty());
    CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == vec);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
}

TEST_CASE("virt_x2apic: inject_spurious - window open")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto spur = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();
    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::disable();
    vapic.inject_spurious(spur);

    CHECK(vapic.irr_is_empty());
    CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == spur);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
}

TEST_CASE("virt_x2apic: inject_spurious - window closed")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto spur = 0xFFU;

    CHECK(vapic.irr_is_empty());
    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    vapic.inject_spurious(spur);
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_x2apic: top_irr")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    std::list<uint8_t> vec = { 0x32U, 0x33U, 0x65U, 0x70U, 0xEFU, 0xF0U, 0xFFU };
    const auto max = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::disable();

    do {
        for (const auto v : vec) {
            vapic.queue_injection(v);
        }
        CHECK(vapic.top_irr() == max);

        for (uint64_t i = 0U; i < vec.size(); ++i) {
            vapic.pop_irr();
        }
        CHECK(vapic.irr_is_empty());

    }
    while (std::next_permutation(vec.begin(), vec.end()));

}

TEST_CASE("virt_x2apic: top_isr")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    std::list<uint8_t> vec = { 0x32U, 0x33U, 0x65U, 0x70U, 0xEFU, 0xF0U, 0xFFU };
    const auto max = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();

    do {
        for (const auto v : vec) {
            vapic.queue_injection(v);
        }
        CHECK(vapic.top_isr() == max);

        for (uint64_t i = 0U; i < vec.size(); ++i) {
            vapic.write_eoi();
        }
        CHECK(vapic.isr_is_empty());

    }
    while (std::next_permutation(vec.begin(), vec.end()));
}

TEST_CASE("virt_x2apic: interrupt_window_exit - single")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    auto vec = 0x80U;

    CHECK(vapic.irr_is_empty());
    CHECK(vapic.isr_is_empty());

    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.isr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.handle_interrupt_window_exit(hve->vmcs());
    CHECK(vapic.irr_is_empty());
    CHECK(proc_ctls1::interrupt_window_exiting::is_disabled());

    CHECK(!vapic.isr_is_empty());
    CHECK(vapic.top_isr() == vec);

    vapic.write_eoi();
    CHECK(vapic.irr_is_empty());
    CHECK(vapic.isr_is_empty());
}

TEST_CASE("virt_x2apic: interrupt_window_exit - permuted")
{
    auto hve = setup_hve();
    auto phys_x2apic = std::make_unique<eapis::intel_x64::phys_x2apic>();
    auto vapic = eapis::intel_x64::virt_x2apic(hve.get(), phys_x2apic.get());
    std::list<uint8_t> vec = { 0x32U, 0x33U, 0x65U, 0x66U, 0xEFU, 0xFEU, 0xFFU };
    const auto max = 0xFFU;

    CHECK(vapic.irr_is_empty());
    CHECK(vapic.isr_is_empty());

    do {
        close_interrupt_window();
        for (const auto v : vec) {
            vapic.queue_injection(v);
            CHECK(!vapic.irr_is_empty());
            CHECK(vapic.isr_is_empty());
            CHECK(proc_ctls1::interrupt_window_exiting::is_enabled());
        }
        CHECK(vapic.top_irr() == max);

        open_interrupt_window();
        for (uint64_t i = 0U; i < vec.size(); ++i) {
            const auto next = vapic.top_irr();
            vapic.handle_interrupt_window_exit(hve->vmcs());
            check_vmentry_interrupt_info(next);
            CHECK(vapic.top_isr() >= next);
            vapic.write_eoi();
        }
        CHECK(vapic.irr_is_empty());
        CHECK(vapic.isr_is_empty());
        CHECK(proc_ctls1::interrupt_window_exiting::is_disabled());

    }
    while (std::next_permutation(vec.begin(), vec.end()));
}

}
}

#endif
