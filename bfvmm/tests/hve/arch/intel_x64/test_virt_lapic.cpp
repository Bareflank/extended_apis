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
#include <hve/arch/intel_x64/phys_lapic.h>
#include <hve/arch/intel_x64/virt_lapic.h>
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

uint32_t g_regs[1024U] = {0U};

TEST_CASE("virt_lapic::virt_lapic")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    CHECK_NOTHROW(vapic);
    CHECK(vapic.read_id() == 0);
}

TEST_CASE("virt_lapic::virt_lapic(hve, phys_lapic)")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto phys_lapic = std::make_unique<eapis::intel_x64::phys_x2apic>();

    CHECK_NOTHROW(eapis::intel_x64::virt_lapic(hve.get(), g_regs, phys_lapic.get()));
}

TEST_CASE("virt_lapic::read_register")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::mmio;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    for (auto i = lapic_n::x2apic_base; i <= lapic_n::x2apic_last; ++i) {
        auto offset = lapic_n::msr_addr_to_offset(i);

        if (lapic_n::readable_in_x2apic(offset)) {
            CHECK(lapic_n::exists_in_x2apic(offset));
            CHECK_NOTHROW(vapic.read_register(offset));
        }
    }
}

TEST_CASE("virt_lapic::write_register")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    for (auto i = lapic_n::x2apic_base; i <= lapic_n::x2apic_last; ++i) {
        auto offset = lapic_n::msr_addr_to_offset(i);

        if (lapic_n::writable_in_x2apic(offset)) {
            CHECK(lapic_n::exists_in_x2apic(offset));
            CHECK_NOTHROW(vapic.write_register(offset, 0x42));
        }
    }
}

TEST_CASE("virt_lapic: reset values")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::mmio;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    CHECK(vapic.read_id() == 0U);
    CHECK(vapic.read_icr() == 0U);
    CHECK(vapic.read_tpr() == 0U);
    CHECK(vapic.read_svr() == lapic_n::svr::reset_value);

    uint64_t ver = 0;
    lapic_n::version::version::set(ver, lapic_n::version::version::reset_value);
    lapic_n::version::max_lvt_entry_minus_one::set(ver, lapic_n::lvt::default_size - 1U);
    lapic_n::version::suppress_eoi_broadcast_supported::disable(ver);

    CHECK(vapic.read_version() == ver);
}

TEST_CASE("virt_lapic: clear values")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    for (auto i = 0U; i < lapic_n::count; ++i) {
        if (!lapic_n::exists_in_x2apic(i)) {
            CHECK(vapic.read_register(i) == 0U);
        }
    }
}

TEST_CASE("virt_lapic: tpr")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto off = lapic_n::msr_addr_to_offset(msrs_n::ia32_x2apic_sivr::addr);

    vapic.write_register(off, 0xFFFFFFFF00000000U);
    CHECK(vapic.read_register(off) ==  0x0U);

    vapic.write_tpr(0xDEADU);
    CHECK(vapic.read_tpr() == 0xDEADU);
}

TEST_CASE("virt_lapic: icr")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto icr0 = lapic_n::msr_addr_to_offset(msrs_n::ia32_x2apic_icr::addr);
    auto icr1 = lapic_n::msr_addr_to_offset(msrs_n::ia32_x2apic_icr::addr | 1U);

    vapic.write_register(icr1, 0xF00DU);
    CHECK(vapic.read_register(icr1) == 0xF00DU);
    CHECK(vapic.read_register(icr0) == 0U);

    vapic.write_register(icr0, 0xBEEFU);
    CHECK(vapic.read_register(icr1) == 0xF00DU);
    CHECK(vapic.read_register(icr0) == 0xBEEFU);

    vapic.write_icr(0x0U);
    CHECK(vapic.read_icr() == 0x0U);

    vapic.write_icr(0xCAFE00000000BABEU);
    CHECK(vapic.read_icr() == 0xCAFE00000000BABEU);
}

TEST_CASE("virt_lapic: self_ipi")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);

    vapic.write_self_ipi(0xFEU);

    auto off = lapic_n::msr_addr_to_offset(msrs_n::ia32_x2apic_self_ipi::addr);
    CHECK(vapic.read_register(off) == 0xFEU);
}

TEST_CASE("virt_lapic: svr")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto off = lapic_n::msr_addr_to_offset(msrs_n::ia32_x2apic_sivr::addr);

    vapic.write_register(off, 0xFFFFFFFF00000000U);
    CHECK(vapic.read_register(off) ==  0x0U);

    vapic.write_svr(0xDEADU);
    CHECK(vapic.read_svr() == 0xDEADU);
}

TEST_CASE("virt_lapic: queue_injection - window closed - rflags.if")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto vec = 100U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_lapic: queue_injection - window closed - blocking by sti")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto vec = 32U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_interruptibility_state::blocking_by_sti::enable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_lapic: queue_injection - window closed - blocking by mov ss")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto vec = 42U;

    CHECK(vapic.irr_is_empty());

    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::enable();
    vapic.queue_injection(vec);

    CHECK(!vapic.irr_is_empty());
    CHECK(vapic.top_irr() == vec);

    vapic.pop_irr();
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_lapic: queue_injection - window open")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto vec = 99U;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();
    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::disable();
    vapic.queue_injection(vec);

    CHECK(vapic.irr_is_empty());
    CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == vec);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
}

TEST_CASE("virt_lapic: inject_spurious - window open")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto spur = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();
    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::disable();
    vapic.inject_spurious(spur);

    CHECK(vapic.irr_is_empty());
    CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == spur);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
}

TEST_CASE("virt_lapic: inject_spurious - window closed")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    auto spur = 0xFFU;

    CHECK(vapic.irr_is_empty());
    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    vapic.inject_spurious(spur);
    CHECK(vapic.irr_is_empty());
}

TEST_CASE("virt_lapic: top_irr")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    std::list<uint8_t> vec = { 0x32U, 0x33U, 0x65U, 0x70U, 0xEFU, 0xF0U, 0xFFU };
    const auto max = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::disable();

    do {
        for (const auto v : vec) {
            vapic.queue_injection(v);
        }
        CHECK(vapic.top_irr() == max);

        for (const auto v : vec) {
            vapic.pop_irr();
        }
        CHECK(vapic.irr_is_empty());

    }
    while (std::next_permutation(vec.begin(), vec.end()));

}

TEST_CASE("virt_lapic: top_isr")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
    std::list<uint8_t> vec = { 0x32U, 0x33U, 0x65U, 0x70U, 0xEFU, 0xF0U, 0xFFU };
    const auto max = 0xFFU;

    vmcs_n::guest_rflags::interrupt_enable_flag::enable();

    do {
        for (const auto v : vec) {
            vapic.queue_injection(v);
        }
        CHECK(vapic.top_isr() == max);

        for (const auto v : vec) {
            vapic.write_eoi();
        }
        CHECK(vapic.isr_is_empty());

    }
    while (std::next_permutation(vec.begin(), vec.end()));
}

TEST_CASE("virt_lapic: interrupt_window_exit - single")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
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

TEST_CASE("virt_lapic: interrupt_window_exit - permuted")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto access = eapis::intel_x64::virt_lapic::access_t::msrs;
    auto vapic = eapis::intel_x64::virt_lapic(hve.get(), g_regs, access);
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
        for (const auto v : vec) {
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
