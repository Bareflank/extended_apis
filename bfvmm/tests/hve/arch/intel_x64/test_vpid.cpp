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

#include <intrinsics.h>

#include <support/arch/intel_x64/test_support.h>
#include <hve/arch/intel_x64/vpid.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;
namespace proc_ctls2 = vmcs_n::secondary_processor_based_vm_execution_controls;

static void setup()
{
    g_msrs[msrs_n::ia32_vmx_true_procbased_ctls::addr] = ~0x0ULL;
    g_msrs[msrs_n::ia32_vmx_procbased_ctls2::addr] = ~0x0ULL;
}

TEST_CASE("vpid::vpid")
{
    setup();

    auto vpid = eapis::intel_x64::vpid();
    CHECK(vpid.id() == 1);
}

TEST_CASE("vpid::enable")
{
    setup();

    auto vpid = eapis::intel_x64::vpid();
    CHECK_NOTHROW(vpid.enable());
    CHECK(proc_ctls2::enable_vpid::is_enabled());
}

}
}

#endif
