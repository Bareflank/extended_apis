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

#include "../../../../../include/support/arch/intel_x64/test_support.h"

namespace ept_p = ::intel_x64::vmcs::ept_pointer;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_vmcs_ept: enable ept")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->enable_ept(0x0000000ABCDEF0000);
    CHECK(ept_p::memory_type::get() == ept_p::memory_type::write_back);
    CHECK(ept_p::page_walk_length_minus_one::get() == 3UL);
    CHECK(ept_p::phys_addr::get() == 0x0000000ABCDEF0000);
    CHECK(proc_ctls2::enable_ept::is_enabled());
}

TEST_CASE("eapis_vmcs_ept: disable ept")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->disable_ept();
    CHECK(ept_p::get() == 0);
    CHECK(proc_ctls2::enable_ept::is_disabled());
}

TEST_CASE("eapis_vmcs_ept: set eptp")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->set_eptp(0x0000000ABCDEF0000);
    CHECK(ept_p::phys_addr::get() == 0x0000000ABCDEF0000);
}

#endif
