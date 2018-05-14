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

#include <bfcapstone.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/vic.h>
#include <arch/intel_x64/apic/lapic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

std::unique_ptr<bfvmm::intel_x64::vmcs> g_vmcs{nullptr};
std::unique_ptr<bfvmm::intel_x64::exit_handler> g_ehlr{nullptr};
std::unique_ptr<eapis::intel_x64::ept::memory_map> g_emap{nullptr};

std::list<std::function<void(void)>> window_closers = {
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

static bool
handle_external_interrupt_stub(
    gsl::not_null<vmcs_t *> vmcs,
    eapis::intel_x64::external_interrupt::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return true;
}

TEST_CASE("vic: constructor")
{
    using namespace msrs_n::ia32_apic_base;

    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto emm = setup_ept();

    disable_lapic();
    CHECK(!lapic_n::is_present());
    CHECK_THROWS(eapis::intel_x64::vic(hve.get(), emm));

    enable_lapic();
    disable_x2apic();
    CHECK(lapic_n::is_present());
    CHECK(!lapic_n::x2apic_supported());
    CHECK_THROWS(eapis::intel_x64::vic(hve.get(), emm));

    enable_x2apic();
    msrs_n::ia32_apic_base::state::enable_xapic();
    CHECK(lapic_n::x2apic_supported());
    CHECK(state::get() == state::xapic);
    CHECK_NOTHROW(eapis::intel_x64::vic(hve.get(), emm));

    msrs_n::ia32_apic_base::state::disable();
    CHECK(state::get() == state::disabled);
    CHECK_THROWS(eapis::intel_x64::vic(hve.get(), emm));

    msrs_n::ia32_apic_base::state::set(msrs_n::ia32_apic_base::state::invalid);
    CHECK(state::get() == state::invalid);
    CHECK_THROWS(eapis::intel_x64::vic(hve.get(), emm));

    msrs_n::ia32_apic_base::state::enable_x2apic();
    CHECK(state::get() == state::x2apic);
    CHECK_NOTHROW(eapis::intel_x64::vic(hve.get(), emm));
}

TEST_CASE("vic: destructor")
{
    {
        MockRepository mocks;
        auto hve = setup_hve(mocks);
        auto vic = setup_vic_x2apic(hve.get());
        ::intel_x64::cr8::set(0U);
        CHECK(::intel_x64::cr8::get() == 0U);
    }

    CHECK(::intel_x64::cr8::get() == 0xFU);
}

TEST_CASE("vic: post x2apic init")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());

    CHECK(lapic_n::is_present());
    CHECK(lapic_n::x2apic_supported());
    CHECK(pin_ctls::external_interrupt_exiting::is_enabled());
    CHECK(exit_ctls::acknowledge_interrupt_on_exit::is_enabled());
    CHECK(::x64::rflags::interrupt_enable_flag::is_disabled());
}

TEST_CASE("vic: post xapic init")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_xapic(hve.get());

    CHECK(lapic_n::is_present());
    CHECK(pin_ctls::external_interrupt_exiting::is_enabled());
    CHECK(exit_ctls::acknowledge_interrupt_on_exit::is_enabled());
    CHECK(::x64::rflags::interrupt_enable_flag::is_disabled());
}

inline void
setup_mm_null_map(MockRepository &mocks)
{
    auto mm = mocks.Mock<bfvmm::memory_manager>();
    mocks.OnCallFunc(bfvmm::memory_manager::instance).Return(mm);
    mocks.OnCall(mm, bfvmm::memory_manager::alloc_map).Return(static_cast<char *>(nullptr));
    mocks.OnCall(mm, bfvmm::memory_manager::free_map);
    mocks.OnCall(mm, bfvmm::memory_manager::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, bfvmm::memory_manager::physint_to_virtptr).Do(physint_to_virtptr);
    mocks.OnCallFunc(bfvmm::x64::map_with_cr3);
    mocks.OnCallFunc(bfvmm::x64::virt_to_phys_with_cr3).Return(0x42);
}

TEST_CASE("vic: init_phys_xapic null map")
{
    MockRepository mocks;

    setup_msrs();
    setup_mm_null_map(mocks);
    setup_pt(mocks);

    g_vmcs = std::make_unique<bfvmm::intel_x64::vmcs>(g_vcpuid);
    g_ehlr = std::make_unique<bfvmm::intel_x64::exit_handler>(g_vmcs.get());
    auto hve = std::make_unique<eapis::intel_x64::hve>(g_ehlr.get(), g_vmcs.get());

    CHECK_THROWS(setup_vic_xapic(hve.get()));
}

TEST_CASE("vic: init_phys_xapic null orig_virt")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);

    g_platform_info.xapic_virt = 0ULL;
    CHECK_THROWS(setup_vic_xapic(hve.get()));
}

TEST_CASE("vic: map n-to-1")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());
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
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());

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
    // When the vic in constructed, an identity map is setup from
    // phys to virt vectors
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());
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

TEST_CASE("vic: ipi - window closed")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());
    auto vec = 200U;

    for (const auto &close_window : window_closers) {
        close_window();

        CHECK_NOTHROW(vic.send_phys_ipi(vec));
        CHECK_NOTHROW(vic.send_virt_ipi(vec++));
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_disabled());

        open_interrupt_window();
    }
}

TEST_CASE("vic: ipi - window open")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());

    open_interrupt_window();

    for (auto i = 32U; i < 256U; ++i) {
        CHECK_NOTHROW(vic.send_phys_ipi(i));
        CHECK_NOTHROW(vic.send_virt_ipi(i));
        CHECK(vmcs_n::vm_entry_interruption_information::vector::get() == i);
        CHECK(vmcs_n::vm_entry_interruption_information::valid_bit::is_enabled());
    }
}

TEST_CASE("vic: handle_interrupt - window closed")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());
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
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());

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
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    const auto spur = 0xFFU;
    msrs_n::ia32_x2apic_sivr::vector::set(spur);
    auto vic = setup_vic_x2apic(hve.get());

    g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
    setup_external_interrupt_exit(spur);
    entry_intr_info::valid_bit::disable();

    for (const auto &close_window : window_closers) {
        close_window();

        ehlr->handle(ehlr);
        CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
        CHECK(entry_intr_info::valid_bit::is_disabled());

        open_interrupt_window();
    }
}

TEST_CASE("vic: handle_spurious_interrupt_exit - window open")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    const auto spur = 0xFFU;
    msrs_n::ia32_x2apic_sivr::vector::set(spur);
    auto vic = setup_vic_x2apic(hve.get());

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
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());

    CHECK_THROWS(vic.add_interrupt_handler(
                     0xDEADBEEFU,
                     vic::handler_delegate_t::create<handle_external_interrupt_stub>())
                );
}

TEST_CASE("vic: handle_interrupt_from_exit - window closed")
{
    namespace entry_intr_info = vmcs_n::vm_entry_interruption_information;

    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    msrs_n::ia32_x2apic_sivr::vector::set(0U);
    auto vic = setup_vic_x2apic(hve.get());

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
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    msrs_n::ia32_x2apic_sivr::vector::set(0U);
    auto vic = setup_vic_x2apic(hve.get());

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
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    entry_intr_info::valid_bit::disable();
    setup_external_interrupt_exit(0x10U);

    g_msrs[msrs_n::ia32_x2apic_eoi::addr] = 0xCAFEBABEU;
    ehlr->handle(ehlr);
    CHECK(g_msrs[msrs_n::ia32_x2apic_eoi::addr] == 0xCAFEBABEU);
    CHECK(entry_intr_info::valid_bit::is_disabled());
}

TEST_CASE("vic: handle_rdmsr_apic_base")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::rdmsr;
    g_save_state.rcx = msrs_n::ia32_apic_base::addr;
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_wrmsr_apic_base")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::wrmsr;
    g_save_state.rcx = msrs_n::ia32_apic_base::addr;
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_rdcr8")
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::control_register_accesses;
    g_vmcs_fields[vmcs_n::exit_qualification::addr] = (access_type::mov_from_cr << access_type::from);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_wrcr8")
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::control_register_accesses;
    g_vmcs_fields[vmcs_n::exit_qualification::addr] = (access_type::mov_to_cr << access_type::from);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_x2apic_read")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto ehlr = hve->exit_handler();
    auto vic = setup_vic_x2apic(hve.get());

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::rdmsr;
    for (auto i = 0U; i < ::intel_x64::lapic::count; ++i) {
        auto addr = ::intel_x64::lapic::offset_to_msr_addr(i);
        if (::intel_x64::lapic::x2apic_readable::is_enabled(addr)) {
            g_save_state.rcx = addr;
            CHECK_NOTHROW(ehlr->handle(ehlr));
        }
    }
}

TEST_CASE("vic: handle_x2apic_write")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_x2apic(hve.get());
    auto ehlr = hve->exit_handler();

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::wrmsr;
    for (auto i = 0U; i < ::intel_x64::lapic::count; ++i) {
        auto addr = ::intel_x64::lapic::offset_to_msr_addr(i);
        if (::intel_x64::lapic::x2apic_writable::is_enabled(addr)) {
            g_save_state.rcx = addr;
            CHECK_NOTHROW(ehlr->handle(ehlr));
        }
    }
}

TEST_CASE("vic: handle_xapic_write base mismatch")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_xapic(hve.get());
    auto ehlr = hve->exit_handler();

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::ept_violation;
    g_vmcs_fields[vmcs_n::guest_physical_address::addr] = 0U;
    ::intel_x64::msrs::ia32_apic_base::apic_base::set(0xFEE00000U);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_xapic_write eoi")
{
    MockRepository mocks;
    auto hve = setup_hve(mocks);
    auto vic = setup_vic_xapic(hve.get());
    auto ehlr = hve->exit_handler();

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::ept_violation;
    g_vmcs_fields[vmcs_n::guest_physical_address::addr] = 0xFEE000B0U;
    ::intel_x64::msrs::ia32_apic_base::apic_base::set(0xFEE00000U);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_xapic_write null guest_rip map")
{
    MockRepository mocks;

    setup_msrs();
    setup_mm_null_map(mocks);
    setup_pt(mocks);

    g_vmcs = std::make_unique<bfvmm::intel_x64::vmcs>(g_vcpuid);
    g_ehlr = std::make_unique<bfvmm::intel_x64::exit_handler>(g_vmcs.get());
    auto hve = std::make_unique<eapis::intel_x64::hve>(g_ehlr.get(), g_vmcs.get());
    auto vic = setup_vic_xapic(hve.get());
    auto ehlr = hve->exit_handler();

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::ept_violation;
    g_vmcs_fields[vmcs_n::guest_physical_address::addr] = 0xFEE00020U;
    ::intel_x64::msrs::ia32_apic_base::apic_base::set(0xFEE00000U);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: handle_xapic_write success")
{
    MockRepository mocks;

    auto hve = setup_hve(mocks);
    auto vic = setup_vic_xapic(hve.get());
    auto ehlr = hve->exit_handler();

    g_vmcs_fields[vmcs_n::exit_reason::addr] = vmcs_n::exit_reason::basic_exit_reason::ept_violation;
    g_vmcs_fields[vmcs_n::guest_physical_address::addr] = 0xFEE00020U;
    ::intel_x64::msrs::ia32_apic_base::apic_base::set(0xFEE00000U);
    CHECK_NOTHROW(ehlr->handle(ehlr));
}

TEST_CASE("vic: verify_xapic_write")
{
    CHECK_THROWS(verify_xapic_write(nullptr));

    cs_insn insn;
    insn.detail = static_cast<cs_detail *>(malloc(sizeof(cs_detail)));
    CHECK(insn.detail != nullptr);

    insn.detail->x86.op_count = 1U;
    CHECK_THROWS(verify_xapic_write(&insn));

    insn.detail->x86.op_count = 2U;
    insn.detail->x86.operands[0U].type = X86_OP_FP;
    CHECK_THROWS(verify_xapic_write(&insn));

    insn.detail->x86.operands[0U].type = X86_OP_IMM;
    CHECK_THROWS(verify_xapic_write(&insn));

    insn.detail->x86.operands[0U].type = X86_OP_REG;
    CHECK_THROWS(verify_xapic_write(&insn));

    insn.detail->x86.operands[0U].type = X86_OP_MEM;
    insn.detail->x86.operands[1U].type = X86_OP_MEM;
    CHECK_NOTHROW(verify_xapic_write(&insn));

    insn.detail->x86.operands[1U].type = X86_OP_REG;
    CHECK_NOTHROW(verify_xapic_write(&insn));

    insn.detail->x86.operands[1U].type = X86_OP_IMM;
    CHECK_NOTHROW(verify_xapic_write(&insn));

    insn.detail->x86.operands[1U].type = X86_OP_FP;
    CHECK_THROWS(verify_xapic_write(&insn));

    free(insn.detail);
}

TEST_CASE("vic: disasm_xapic_write expects error")
{
    csh cs;
    cs_insn *insn;
    const uint8_t rip[1] = { 0xC3U };

    CHECK_THROWS(disasm_xapic_write(nullptr, &insn, rip));
    CHECK_THROWS(disasm_xapic_write(&cs, nullptr, rip));
    CHECK_THROWS(disasm_xapic_write(&cs, &insn, nullptr));
}

TEST_CASE("vic: disasm_xapic_write cs_open error")
{
    csh cs;
    cs_insn *insn;
    const uint8_t rip[1] = { 0xC3U };

    MockRepository mocks;
    mocks.OnCallFunc(cs_open).Return(static_cast<cs_err>(CS_ERR_OK + 1U));
    CHECK_THROWS(disasm_xapic_write(&cs, &insn, rip));
}

TEST_CASE("vic: disasm_xapic_write nr_disasm != need")
{
    csh cs;
    cs_insn *insn;
    const uint8_t rip[1] = { 0xC3U };

    MockRepository mocks;
    mocks.OnCallFunc(cs_disasm).Return(0U);
    CHECK_THROWS(disasm_xapic_write(&cs, &insn, rip));
}

TEST_CASE("vic: disasm_xapic_write success")
{
    csh cs;
    cs_insn *insn;
    const uint8_t rip[1] = { 0xC3U };

    g_vmcs_fields[vmcs_n::vm_exit_instruction_length::addr] = 1U;
    disasm_xapic_write(&cs, &insn, rip);
    CHECK(insn != nullptr);

    free(insn);
}

}
}

#endif
