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

#include <bfsupport.h>
#include <bfvmm/memory_manager/memory_manager.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/apic/vic.h>
#include <arch/intel_x64/apic/lapic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace msrs_n::ia32_apic_base;
namespace proc_ctls1 = vmcs_n::primary_processor_based_vm_execution_controls;

namespace eapis
{
namespace intel_x64
{

std::unique_ptr<bfvmm::intel_x64::vmcs> g_vmcs{nullptr};
std::unique_ptr<bfvmm::intel_x64::exit_handler> g_ehlr{nullptr};
std::unique_ptr<eapis::intel_x64::ept::memory_map> g_emap{nullptr};

std::array<std::function<void(void)>, 3> window_closers = {
    []() { ::x64::rflags::interrupt_enable_flag::disable(); },
    []() { vmcs_n::guest_interruptibility_state::blocking_by_sti::enable(); },
    []() { vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::enable(); }
};

static auto
setup_external_interrupt_exit(uint64_t vector)
{
    namespace reason = vmcs_n::exit_reason::basic_exit_reason;
    namespace info = vmcs_n::vm_exit_interruption_information;

    auto val = g_vmcs_fields[vmcs_n::exit_reason::addr];
    val = set_bits(
              val, reason::mask, (reason::external_interrupt << reason::from)
          );
    g_vmcs_fields[vmcs_n::exit_reason::addr] = val;

    auto vec = g_vmcs_fields[info::addr];
    vec = set_bits(
              vec, info::vector::mask, (vector << info::vector::from)
          );
    g_vmcs_fields[info::addr] = vec;
}

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<bfvmm::memory_manager>();
    mocks.OnCallFunc(bfvmm::memory_manager::instance).Return(mm);
    mocks.OnCall(mm, bfvmm::memory_manager::virtptr_to_physint).Return(0xCAFE000);

    return mm;
}

static bool
handle_external_interrupt_stub(
    gsl::not_null<vmcs_t *> vmcs,
    eapis::intel_x64::external_interrupt::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return true;
}

TEST_CASE("vic: lapic not present")
{
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    disable_lapic();

    CHECK(!lapic_n::is_present());
    CHECK_THROWS(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: x2apic not supported")
{
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    enable_lapic();
    disable_x2apic();

    CHECK(lapic_n::is_present());
    CHECK(!lapic_n::x2apic_supported());
    CHECK_THROWS(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: xapic mode")
{
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    enable_lapic();
    enable_x2apic();

    msrs_n::ia32_apic_base::state::enable_xapic();
    CHECK(lapic_n::x2apic_supported());
    CHECK(state::get() == state::xapic);
    CHECK_NOTHROW(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: lapic disabled")
{
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    enable_lapic();
    enable_x2apic();

    msrs_n::ia32_apic_base::state::disable();
    CHECK(state::get() == state::disabled);
    CHECK_THROWS(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: lapic invalid")
{
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    enable_lapic();
    enable_x2apic();

    msrs_n::ia32_apic_base::state::set(msrs_n::ia32_apic_base::state::invalid);
    CHECK(state::get() == state::invalid);
    CHECK_THROWS(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: success with no efi")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = false;
    setup_x2apic();

    CHECK(state::get() == state::x2apic);
    CHECK_NOTHROW(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: success with efi")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    get_platform_info()->efi.enabled = true;
    setup_x2apic();

    CHECK(lapic_n::x2apic_supported());
    CHECK(state::get() == state::x2apic);
    CHECK_NOTHROW(eapis::intel_x64::vic(hve.get()));
}

TEST_CASE("vic: destructor")
{
    {
        MockRepository mocks;
        get_platform_info()->efi.enabled = false;
        auto mm = setup_mm(mocks);
        auto hve = setup_hve();
        auto vic = setup_vic(hve.get());

        ::intel_x64::cr8::set(0U);
        CHECK(::intel_x64::cr8::get() == 0U);
    }

    CHECK(::intel_x64::cr8::get() == 0xFU);
}

TEST_CASE("vic: post x2apic init")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());

    CHECK(lapic_n::is_present());
    CHECK(lapic_n::x2apic_supported());
    CHECK(pin_ctls::external_interrupt_exiting::is_enabled());
    CHECK(exit_ctls::acknowledge_interrupt_on_exit::is_enabled());
    CHECK(::x64::rflags::interrupt_enable_flag::is_disabled());
}

TEST_CASE("vic: map n-to-1")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());
    const auto virt = 42U;

    for (auto phys = 32U; phys < 256U; ++phys) {
        vic.map(phys, virt);
    }

    for (auto phys = 32U; phys < 256U; ++phys) {
        CHECK(vic.phys_to_virt(phys) == virt);
        CHECK(vic.virt_to_phys(virt) == 255U);
    }

    vic.unmap(virt);
    for (auto phys = 32U; phys < 256U; ++phys) {
        CHECK(vic.phys_to_virt(phys) == 0U);
    }
}

TEST_CASE("vic: map identity")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());

    for (auto i = 32U; i < 256U; ++i) {
        vic.map(i, i);
    }

    for (auto i = 32U; i < 256U; ++i) {
        CHECK(vic.phys_to_virt(i) == i);
        CHECK(vic.virt_to_phys(i) == i);
    }

    vic.unmap(42U);

    for (auto i = 32U; i < 256U; ++i) {
        if (i == 42U) {
            CHECK(vic.phys_to_virt(i) == 0U);
            continue;
        }
        CHECK(vic.phys_to_virt(i) == i);
    }
}

TEST_CASE("vic: virt_to_phys")
{
    // When the vic is constructed, an identity map is setup from
    // phys to virt vectors
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());
    auto phys = 32U;
    auto virt = 56U;

    vic.map(phys, virt);
    vic.map(phys + 1U, virt + 1U);

    // virt_to_phys starts at the highest-priority phys vector
    // and walks down until (at(phys) == virt)
    CHECK(vic.virt_to_phys(100U) == 100U);
    CHECK(vic.virt_to_phys(virt) == virt);
    CHECK(vic.virt_to_phys(virt + 1U) == virt + 1U);
}

TEST_CASE("vic: handle_interrupt - window closed")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());
    auto phys = 32U;

    vmcs_n::vm_entry_interruption_information::valid_bit::disable();

    for (const auto &close_window : window_closers) {
        close_window();

        g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xFFU;
        vic.handle_interrupt(phys++);
        CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0U);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());

        open_interrupt_window();
    }
}

TEST_CASE("vic: handle_interrupt - window open")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());

    vmcs_n::vm_entry_interruption_information::valid_bit::disable();
    open_interrupt_window();

    for (auto i = 32U; i < 256U; ++i) {
        g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xFFU;
        vic.handle_interrupt(i);

        CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0U);
        CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == i);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
    }
}

TEST_CASE("vic: handle_spurious_interrupt_exit - window closed")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();
    get_platform_info()->efi.enabled = false;

    const auto spur = 0xFFU;
    msrs_n::ia32_x2apic_sivr::vector::set(spur);
    auto vic = setup_vic(hve.get());

    g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
    setup_external_interrupt_exit(spur);
    vmcs_n::vm_entry_interruption_information::valid_bit::disable();

    window_closers[0]();
    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    open_interrupt_window();

    window_closers[1]();
    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    open_interrupt_window();

    window_closers[2]();
    vmcs_n::guest_rflags::interrupt_enable_flag::disable();
    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());
    open_interrupt_window();
}

TEST_CASE("vic: handle_spurious_interrupt_exit - window open")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();
    const auto spur = 0xFFU;
    msrs_n::ia32_x2apic_sivr::vector::set(spur);
    auto vic = setup_vic(hve.get());

    g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
    setup_external_interrupt_exit(spur);
    entry_intr_info::valid_bit::disable();
    open_interrupt_window();

    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(entry_intr_info::vector::get() == spur);
    CHECK(entry_intr_info::valid_bit::is_enabled());
}

TEST_CASE("vic: add_interrupt_handler")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto vic = setup_vic(hve.get());

    CHECK_THROWS(vic.add_interrupt_handler(
                     0xDEADBEEFU,
                     vic::handler_delegate_t::create<handle_external_interrupt_stub>())
                );
}

TEST_CASE("vic: handle_interrupt_from_exit - window closed")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();
    msrs_n::ia32_x2apic_sivr::vector::set(0U);
    auto vic = setup_vic(hve.get());

    entry_intr_info::valid_bit::disable();
    close_interrupt_window();

    for (auto v = 32U; v < 34U; ++v) {
        setup_external_interrupt_exit(v);
        g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;

        ehlr->handle(ehlr);
        CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0U);
        CHECK(proc_ctls1::interrupt_window_exiting::is_enabled());
        CHECK(entry_intr_info::valid_bit::is_disabled());
    }
}

TEST_CASE("vic: handle_interrupt_from_exit - window open")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();
    msrs_n::ia32_x2apic_sivr::vector::set(0U);
    auto vic = setup_vic(hve.get());

    entry_intr_info::valid_bit::disable();
    open_interrupt_window();

    for (auto v = 32U; v < 256U; ++v) {
        g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
        setup_external_interrupt_exit(v);

        ehlr->handle(ehlr);
        CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0U);
        CHECK(entry_intr_info::vector::get() == v);
        CHECK(entry_intr_info::valid_bit::is_enabled());
    }
}

TEST_CASE("vic: handle_external_interrupt_exit - invalid vector")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto mm = setup_mm(mocks);
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic(hve.get());

    entry_intr_info::valid_bit::disable();
    setup_external_interrupt_exit(0x10U);

    g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(entry_intr_info::valid_bit::is_disabled());
}

//TEST_CASE("vic: handle_rdmsr_apic_base")
//{
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto ehlr = hve->exit_handler();
//    auto vic = setup_vic(hve.get());
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::rdmsr;
//    g_save_state.rcx = msrs_n::ia32_apic_base::addr;
//    CHECK_NOTHROW(ehlr->handle(ehlr));
//}

//TEST_CASE("vic: handle_wrmsr_apic_base")
//{
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto ehlr = hve->exit_handler();
//    auto vic = setup_vic(hve.get());
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::wrmsr;
//    g_save_state.rcx = msrs_n::ia32_apic_base::addr;
//    CHECK_NOTHROW(ehlr->handle(ehlr));
//}

//TEST_CASE("vic: handle_rdcr8")
//{
//    using namespace vmcs_n::exit_qualification::control_register_access;
//
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto ehlr = hve->exit_handler();
//    auto vic = setup_vic(hve.get());
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::control_register_accesses;
//    g_vmcs_fields[vmcs_n::exit_qualification::addr] = (access_type::mov_from_cr << access_type::from);
//    CHECK_NOTHROW(ehlr->handle(ehlr));
//}
//
//TEST_CASE("vic: handle_wrcr8")
//{
//    using namespace vmcs_n::exit_qualification::control_register_access;
//
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto ehlr = hve->exit_handler();
//    auto vic = setup_vic(hve.get());
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::control_register_accesses;
//    g_vmcs_fields[vmcs_n::exit_qualification::addr] = (access_type::mov_to_cr << access_type::from);
//    CHECK_NOTHROW(ehlr->handle(ehlr));
//}
//
//TEST_CASE("vic: handle_x2apic_read")
//{
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto ehlr = hve->exit_handler();
//    auto vic = setup_vic(hve.get());
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::rdmsr;
//    for (const auto i : ::intel_x64::lapic::offset::list) {
//        auto addr = ::intel_x64::lapic::offset::to_msr_addr(i);
//        if (::intel_x64::lapic::x2apic_readable::is_enabled(i)) {
//            g_save_state.rcx = addr;
//            CHECK_NOTHROW(ehlr->handle(ehlr));
//        }
//    }
//}
//
//TEST_CASE("vic: handle_x2apic_write")
//{
//    MockRepository mocks;
//    auto mm = setup_mm(mocks);
//    auto hve = setup_hve();
//    auto vic = setup_vic(hve.get());
//    auto ehlr = hve->exit_handler();
//
//    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::wrmsr;
//    for (const auto i : ::intel_x64::lapic::offset::list) {
//        auto addr = ::intel_x64::lapic::offset::to_msr_addr(i);
//        if (::intel_x64::lapic::x2apic_writable::is_enabled(i)) {
//            g_save_state.rcx = addr;
//            CHECK_NOTHROW(ehlr->handle(ehlr));
//        }
//    }
//}

}
}

#endif
