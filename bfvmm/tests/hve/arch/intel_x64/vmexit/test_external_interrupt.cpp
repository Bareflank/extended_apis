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
#include <hve/arch/intel_x64/vmexit/external_interrupt.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt_handler::info_t &info)
{
    bfignored(info);
    bfignored(vmcs);

    return true;
}

bool
test_handler_returns_false(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt_handler::info_t &info)
{
    bfignored(info);
    bfignored(vmcs);

    return false;
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(external_interrupt_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("add handlers")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(
        handler.add_handler(
            external_interrupt_handler::handler_delegate_t::create<test_handler>()
        )
    );
}

TEST_CASE("enable/disable")
{
    setup_eapis_test_support();

    using namespace vmcs_n::vm_exit_controls;
    using namespace vmcs_n::pin_based_vm_execution_controls;

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    handler.enable_exiting();
    CHECK(external_interrupt_exiting::is_enabled());
    CHECK(acknowledge_interrupt_on_exit::is_enabled());

    handler.disable_exiting();
    CHECK(external_interrupt_exiting::is_disabled());
    CHECK(acknowledge_interrupt_on_exit::is_disabled());
}

TEST_CASE("external interrupt log")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        external_interrupt_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("external interrupt exit")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        external_interrupt_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
}

TEST_CASE("external interrupt exit, no handler")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("external interrupt exit, returns false")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = external_interrupt_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        external_interrupt_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK_THROWS(handler.handle(vmcs));
}

#endif
