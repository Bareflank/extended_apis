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
#include <hve/arch/intel_x64/sipi.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool test_handler(gsl::not_null<vmcs_t *>)
{
    return true;
}

namespace eapis
{
namespace intel_x64
{

TEST_CASE("sipi::sipi")
{
    auto hve = setup_hve();

    CHECK_NOTHROW(eapis::intel_x64::sipi(hve.get()));
}

TEST_CASE("sipi::add_handler")
{
    auto hve = setup_hve();
    auto sipi = eapis::intel_x64::sipi(hve.get());
    auto hdlr = sipi::handler_delegate_t::create<test_handler>();

    CHECK_NOTHROW(sipi.add_handler(std::move(hdlr)));
}

TEST_CASE("sipi::handle")
{
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();

    namespace reason = vmcs_n::exit_reason::basic_exit_reason;

    auto sipi = eapis::intel_x64::sipi(hve.get());
    auto hdlr = sipi::handler_delegate_t::create<test_handler>();
    sipi.add_handler(std::move(hdlr));
    g_vmcs_fields[vmcs_n::exit_reason::addr] = reason::sipi;

    CHECK_NOTHROW(ehlr->handle(ehlr));
}

}
}

#endif
