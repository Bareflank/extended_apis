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

#include <test_support.h>

using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
std::map<intel_x64::vmcs::field_type, intel_x64::vmcs::value_type> g_vmcs;

uintptr_t g_rip = 0;
uintptr_t g_cr8 = 0;
uintptr_t g_rflags = 0;
state_save_intel_x64 g_state_save{};
bool g_monitor_trap_callback_called = false;

bool g_enable_vpid = false;
bool g_enable_io_bitmaps = false;
bool g_enable_msr_bitmap = false;
exit_handler_intel_x64_eapis::port_type g_port = 0;
exit_handler_intel_x64_eapis::msr_type g_rdmsr = 0;
exit_handler_intel_x64_eapis::msr_type g_wrmsr = 0;

extern "C" bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs[field];
    return true;
}

extern "C"  bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs[field] = val;
    return true;
}

extern "C" uint64_t
test_read_cr8() noexcept
{ return g_cr8; }

extern "C" void
test_write_cr8(uint64_t val) noexcept
{ g_cr8 = val; }

extern "C" uint64_t
test_read_rflags() noexcept
{ return g_rflags; }

extern "C" void
test_write_rflags(uint64_t val) noexcept
{ g_rflags = val; }

extern "C" uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" void
test_stop(void) noexcept
{ }

vmcs_intel_x64_eapis *
setup_vmcs(MockRepository &mocks, vmcs::value_type reason, vmcs::value_type qualification)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64_eapis>();

    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::launch);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::resume);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::promote);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::load);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::clear);

    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::enable_vpid).Do([&] { g_enable_vpid = true; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::disable_vpid).Do([&] { g_enable_vpid = false; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::enable_io_bitmaps).Do([&] { g_enable_io_bitmaps = true; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::disable_io_bitmaps).Do([&] { g_enable_io_bitmaps = false; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_io_access).Do([&](auto port) { g_port = port; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_all_io_accesses).Do([&]() { g_port = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_io_access).Do([&](auto port) { g_port = port; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_all_io_accesses).Do([&]() { g_port = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::whitelist_io_access).Do([&](auto ports) { g_port = ports[0]; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::blacklist_io_access).Do([&](auto ports) { g_port = ports[0]; });

    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::enable_msr_bitmap).Do([&] { g_enable_msr_bitmap = true; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::disable_msr_bitmap).Do([&] { g_enable_msr_bitmap = false; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_rdmsr_access).Do([&](auto msr) { g_rdmsr = msr; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_wrmsr_access).Do([&](auto msr) { g_wrmsr = msr; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_all_rdmsr_accesses).Do([&]() { g_rdmsr = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_all_wrmsr_accesses).Do([&]() { g_wrmsr = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_rdmsr_access).Do([&](auto msr) { g_rdmsr = msr; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_wrmsr_access).Do([&](auto msr) { g_wrmsr = msr; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_all_rdmsr_accesses).Do([&]() { g_rdmsr = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_all_wrmsr_accesses).Do([&]() { g_wrmsr = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::whitelist_rdmsr_access).Do([&](auto msrs) { g_rdmsr = msrs[0]; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::whitelist_wrmsr_access).Do([&](auto msrs) { g_wrmsr = msrs[0]; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::blacklist_rdmsr_access).Do([&](auto msrs) { g_rdmsr = msrs[0]; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::blacklist_wrmsr_access).Do([&](auto msrs) { g_wrmsr = msrs[0]; });

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    g_vmcs[vmcs::exit_reason::addr] = reason;
    g_vmcs[vmcs::exit_qualification::addr] = qualification;
    g_vmcs[vmcs::vm_exit_instruction_length::addr] = 8;
    g_vmcs[vmcs::vm_exit_instruction_information::addr] = 0;

    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
    mocks.OnCallFunc(_read_cr8).Do(test_read_cr8);
    mocks.OnCallFunc(_write_cr8).Do(test_write_cr8);
    mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
    mocks.OnCallFunc(_write_rflags).Do(test_write_rflags);
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);
    mocks.OnCallFunc(_stop).Do(test_stop);

    return vmcs;
}

std::unique_ptr<exit_handler_ut>
setup_ehlr(gsl::not_null<vmcs_intel_x64_eapis *> vmcs)
{
    auto ehlr = std::make_unique<exit_handler_ut>();
    ehlr->set_vmcs(vmcs);
    ehlr->set_state_save(&g_state_save);

    g_rip = ehlr->m_state_save->rip + g_vmcs[vmcs::vm_exit_instruction_length::addr];
    return ehlr;
}

#endif
