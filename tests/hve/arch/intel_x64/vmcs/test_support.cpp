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

static std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
static std::map<intel_x64::vmcs::field_type, intel_x64::vmcs::value_type> g_vmcs;

bool
vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs[field];
    return true;
}

bool
vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs[field] = val;
    return true;
}

uint64_t
read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

bool
vmclear(void *ptr) noexcept
{ (void)ptr; return true; }

bool
vmptrld(void *ptr) noexcept
{ (void)ptr; return true; }

bool
vmlaunch_demote() noexcept
{ return true; }

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

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    mocks.OnCallFunc(_vmread).Do(vmread);
    mocks.OnCallFunc(_vmwrite).Do(vmwrite);
    mocks.OnCallFunc(_read_msr).Do(read_msr);
    mocks.OnCallFunc(_vmclear).Do(vmclear);
    mocks.OnCallFunc(_vmptrld).Do(vmptrld);
    mocks.OnCallFunc(_vmlaunch_demote).Do(vmlaunch_demote);

    return vmcs;
}

#endif
