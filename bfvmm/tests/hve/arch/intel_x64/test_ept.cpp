//
// Bareflank Extended APIs
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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>
#include <hve/arch/intel_x64/ept.h>

using namespace eapis::intel_x64;

TEST_CASE("constructor")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(ept_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("set_eptp")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = ept_handler(eapis, &g_eapis_vcpu_global_state);

    auto mm = ept::mmap{};

    handler.set_eptp(&mm);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());

    handler.set_eptp(nullptr);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_disabled());

    handler.set_eptp(&mm);
    handler.set_eptp(&mm);
    handler.set_eptp(&mm);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());

    handler.set_eptp(nullptr);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_disabled());
}
