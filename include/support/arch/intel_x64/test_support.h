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

#ifndef TEST_SUPPORT_EAPIS_H
#define TEST_SUPPORT_EAPIS_H

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <memory>
#include <bfgsl.h>
#include <intrinsics.h>
#include <bfvmm/memory_manager/memory_manager_x64.h>

#include "../../../hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../hve/arch/intel_x64/exit_handler/exit_handler.h"
#include "../../../hve/arch/intel_x64/exit_handler/vmcall_interface.h"

namespace intel = intel_x64;
namespace msrs = intel_x64::msrs;
namespace vmcs = intel_x64::vmcs;
namespace exit_ctls = vmcs::vm_exit_controls;
namespace entry_ctls = vmcs::vm_entry_controls;
namespace pin_ctls = vmcs::pin_based_vm_execution_controls;
namespace proc_ctls = vmcs::primary_processor_based_vm_execution_controls;
namespace proc_ctls2 = vmcs::secondary_processor_based_vm_execution_controls;

extern bool g_deny_all;
extern bool g_log_denials;

std::map<msrs::field_type, msrs::value_type> g_msrs;
std::map<vmcs::field_type, vmcs::value_type> g_vmcs;
std::map<uint32_t, uint32_t> g_eax_cpuid;
std::map<uint32_t, uint32_t> g_ebx_cpuid;
std::map<uint32_t, uint32_t> g_ecx_cpuid;

state_save_intel_x64 g_state_save;

uintptr_t g_rip;
uint64_t g_cr8;
uint64_t g_rflags;

bool g_monitor_trap_callback_called;
bool g_enable_vpid;
bool g_enable_io_bitmaps;
bool g_enable_msr_bitmap;

exit_handler_intel_x64_eapis::port_type g_port;
exit_handler_intel_x64_eapis::msr_type g_rdmsr;
exit_handler_intel_x64_eapis::msr_type g_wrmsr;

class exit_handler_ut : public exit_handler_intel_x64_eapis
{
public:
    void monitor_trap_callback()
    {
        g_monitor_trap_callback_called = true;
    }
};

vmcs_intel_x64_eapis *
setup_vmcs(MockRepository &mocks,
    vmcs::value_type reason,
    vmcs::value_type qualification = 0)
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

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    g_vmcs[vmcs::exit_reason::addr] = reason;
    g_vmcs[vmcs::exit_qualification::addr] = qualification;
    g_vmcs[vmcs::vm_exit_instruction_length::addr] = 8;
    g_vmcs[vmcs::vm_exit_instruction_information::addr] = 0;

    //mocks.OnCallFunc(_vmread).Do(test_vmread);
    //mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
    //mocks.OnCallFunc(_read_cr8).Do(test_read_cr8);
    //mocks.OnCallFunc(_write_cr8).Do(test_write_cr8);
    //mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
    //mocks.OnCallFunc(_write_rflags).Do(test_write_rflags);
    //mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    //mocks.OnCallFunc(_write_msr).Do(test_write_msr);
    //mocks.OnCallFunc(_stop).Do(test_stop);

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

memory_manager_x64 *
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);
    mocks.OnCall(mm, memory_manager_x64::virtint_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

std::unique_ptr<vmcs_intel_x64_eapis>
setup_vmcs(MockRepository &mocks)
{
    auto vmcs = std::make_unique<vmcs_intel_x64_eapis>();

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    (void)mocks;
    //mocks.OnCallFunc(_vmread).Do(vmread);
    //mocks.OnCallFunc(_vmwrite).Do(vmwrite);
    //mocks.OnCallFunc(_read_msr).Do(read_msr);
    //mocks.OnCallFunc(_vmclear).Do(vmclear);
    //mocks.OnCallFunc(_vmptrld).Do(vmptrld);
    //mocks.OnCallFunc(_vmlaunch_demote).Do(vmlaunch_demote);

    return vmcs;
}

extern "C" uint64_t
thread_context_cpuid(void)
{
    return 0;
}

extern "C" uint64_t
thread_context_tlsptr(void)
{
    return 0;
}

extern "C" void
vmcs_launch(state_save_intel_x64 *state_save) noexcept
{
    bfignored(state_save);
}

extern "C" void
vmcs_promote(state_save_intel_x64 *state_save, const void *guest_gdt) noexcept
{
    bfignored(state_save);
    bfignored(guest_gdt);
}

extern "C" void
vmcs_resume(state_save_intel_x64 *state_save) noexcept
{
    bfignored(state_save);
}

extern "C" void _cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    *reinterpret_cast<uint32_t *>(eax) = 0;
    *reinterpret_cast<uint32_t *>(ebx) = 0;
    *reinterpret_cast<uint32_t *>(ecx) = 0;
    *reinterpret_cast<uint32_t *>(edx) = 0;
}

extern "C" uint32_t
_cpuid_subebx(uint32_t val, uint32_t sub) noexcept
{
    bfignored(sub);
    return g_ebx_cpuid[val];
}

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{
    return g_msrs[addr];
}

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{
    g_msrs[addr] = val;
}

extern "C" uint64_t
_read_cr8() noexcept
{
    return g_cr8;
}

extern "C" void
_write_cr8(uint64_t val) noexcept
{
    g_cr8 = val;
}

extern "C" uint64_t
_read_rflags() noexcept
{
    return g_rflags;
}

extern "C" void
_write_rflags(uint64_t val) noexcept
{
    g_rflags = val;
}

extern "C" void
_stop(void) noexcept
{
}

extern "C" bool
_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs[field];
    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs[field] = val;
    return true;
}

extern "C" bool
_vmclear(void *ptr) noexcept
{
    (void)ptr; return true;
}

extern "C" bool
_vmptrld(void *ptr) noexcept
{
    (void)ptr; return true;
}

extern "C" bool
_vmlaunch_demote() noexcept
{
    return true;
}

extern "C" void
_wbinvd() noexcept
{
}

extern "C" uint32_t
_cpuid_eax(uint32_t val) noexcept
{
    return g_eax_cpuid[val];
}

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{
    return g_ecx_cpuid[val];
}

extern "C" bool
_invept(uint64_t type, void *ptr) noexcept
{
    bfignored(type);
    bfignored(ptr);
    return true;
}

extern "C" void
_invlpg(const void *addr) noexcept
{
    bfignored(addr);
    return;
}

#endif
