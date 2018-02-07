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

namespace reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_exit_handler_rdmsr_emulation: exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, reason::rdmsr);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_rdmsr_access(true);
    ehlr->m_state_save->rcx = 42;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(ehlr->m_rdmsr_access_log[42] == 1);
}

#endif
