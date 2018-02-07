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

namespace intel = bfvmm::intel_x64;
namespace vmcs_eapis = eapis::hve::intel_x64::vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_vmcs: construction / destruction")
{
    CHECK_NOTHROW(std::make_unique<vmcs_eapis::vmcs>());
}

TEST_CASE("eapis_vmcs: launch")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);
    auto vmss = std::make_unique<intel::vmcs_state>();

    vmcs->launch(vmss.get(), vmss.get());
}

#endif
