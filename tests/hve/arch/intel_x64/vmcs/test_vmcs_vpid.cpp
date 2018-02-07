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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

#include "../../../../../include/support/arch/intel_x64/test_support.h"

namespace vpi = ::intel_x64::vmcs::virtual_processor_identifier;


TEST_CASE("eapis_vmcs_vpid: enable vpid")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    vmcs->enable_vpid();

    CHECK(proc_ctls2::enable_vpid::is_enabled());
    CHECK(vpi::get() != 0);
}

TEST_CASE("eapis_vmcs_vpid: disable vpid")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);

    vmcs->disable_vpid();

    CHECK(proc_ctls2::enable_vpid::is_disabled());
    CHECK(vpi::get() == 0);
}

#endif
