//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
