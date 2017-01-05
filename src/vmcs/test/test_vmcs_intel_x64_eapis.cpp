//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <test.h>
#include <memory_manager/memory_manager_x64.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

static std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
static std::map<intel_x64::vmcs::field_type, intel_x64::vmcs::value_type> g_vmcs;

extern "C" bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs[field];
    return true;
}

extern "C"  bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs[field] = val;
    return true;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" bool
__vmclear(void *ptr) noexcept
{ (void)ptr; return true; }

extern "C" bool
__vmptrld(void *ptr) noexcept
{ (void)ptr; return true; }

extern "C" bool
__vmlaunch_demote(void) noexcept
{ return true; }

extern "C" bool
__invept(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return true; }

extern "C" bool
__invvpid(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return true; }

uintptr_t
virtptr_to_physint(void *ptr)
{ (void) ptr; return 0x0000000000042000UL; }

auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Do(virtptr_to_physint);

    return mm;
}

auto
setup_vmcs()
{
    auto &&vmcs = std::make_unique<vmcs_intel_x64_eapis>();

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    return std::move(vmcs);
}

void
eapis_ut::test_construction()
{
    this->expect_no_exception([&] { std::make_unique<vmcs_intel_x64_eapis>(); });
}

void
eapis_ut::test_launch()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&vmcs = setup_vmcs();
    auto &&vmss = std::make_unique<vmcs_intel_x64_state>();

    vmcs->launch(vmss.get(), vmss.get());

    this->expect_true(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
    this->expect_true(address_of_io_bitmap_a::get() != 0);
    this->expect_true(address_of_io_bitmap_b::get() != 0);

    this->expect_true(secondary_processor_based_vm_execution_controls::enable_vpid::is_disabled());
}

void
eapis_ut::test_enable_vpid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->enable_vpid();

    this->expect_true(secondary_processor_based_vm_execution_controls::enable_vpid::is_enabled());
    this->expect_true(vmcs::virtual_processor_identifier::get() != 0);
}

void
eapis_ut::test_disable_vpid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->disable_vpid();

    this->expect_true(secondary_processor_based_vm_execution_controls::enable_vpid::is_disabled());
    this->expect_true(vmcs::virtual_processor_identifier::get() == 0);
}

void
eapis_ut::test_trap_on_io_access()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->trap_on_io_access(0x42);
    vmcs->trap_on_io_access(0x8042);

    this->expect_true(vmcs->m_io_bitmapa_view[8] == 0x4);
    this->expect_true(vmcs->m_io_bitmapb_view[8] == 0x4);
}

void
eapis_ut::test_trap_on_all_io_accesses()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->trap_on_all_io_accesses();

    auto all_seta = 0xFF;
    for (auto val : vmcs->m_io_bitmapa_view)
        all_seta &= val;

    this->expect_true(all_seta == 0xFF);

    auto all_setb = 0xFF;
    for (auto val : vmcs->m_io_bitmapa_view)
        all_setb &= val;

    this->expect_true(all_setb == 0xFF);
}

void
eapis_ut::test_pass_through_io_access()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->trap_on_all_io_accesses();
    vmcs->pass_through_io_access(0x42);
    vmcs->pass_through_io_access(0x8042);

    this->expect_true(vmcs->m_io_bitmapa_view[8] == 0xFB);
    this->expect_true(vmcs->m_io_bitmapb_view[8] == 0xFB);
}

void
eapis_ut::test_pass_through_all_io_accesses()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->pass_through_all_io_accesses();

    auto all_seta = 0x0;
    for (auto val : vmcs->m_io_bitmapa_view)
        all_seta |= val;

    this->expect_true(all_seta == 0x0);

    auto all_setb = 0x0;
    for (auto val : vmcs->m_io_bitmapa_view)
        all_setb |= val;

    this->expect_true(all_setb == 0x0);
}

void
eapis_ut::test_whitelist_io_access()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->whitelist_io_access({0x42, 0x8042});
    this->expect_true(vmcs->m_io_bitmapa_view[8] == 0xFB);
    this->expect_true(vmcs->m_io_bitmapb_view[8] == 0xFB);
}

void
eapis_ut::test_blacklist_io_access()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs();

    vmcs->blacklist_io_access({0x42, 0x8042});
    this->expect_true(vmcs->m_io_bitmapa_view[8] == 0x4);
    this->expect_true(vmcs->m_io_bitmapb_view[8] == 0x4);
}

void
eapis_ut::test_enable_ept()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&vmcs = setup_vmcs();

    vmcs->enable_ept();
    this->expect_true(secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());
}

void
eapis_ut::test_disable_ept()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&vmcs = setup_vmcs();

    vmcs->disable_ept();
    this->expect_true(ept_pointer::get() == 0);
    this->expect_true(secondary_processor_based_vm_execution_controls::enable_ept::is_disabled());
}

void
eapis_ut::test_set_eptp()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&vmcs = setup_vmcs();

    vmcs->set_eptp(0x0000000ABCDEF0000);
    this->expect_true(ept_pointer::memory_type::get() == ept_pointer::memory_type::write_back);
    this->expect_true(ept_pointer::page_walk_length_minus_one::get() == 3UL);
    this->expect_true(ept_pointer::phys_addr::get() == 0x0000000ABCDEF0000);
}
