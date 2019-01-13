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
#include <hve/arch/intel_x64/vmexit/interrupt_window.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, interrupt_window_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return true;
}

bool
test_handler_returns_false(
    gsl::not_null<vmcs_t *> vmcs, interrupt_window_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return false;
}

bool
test_handler_ignore_disable(
    gsl::not_null<vmcs_t *> vmcs, interrupt_window_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    info.ignore_disable = true;
    return true;
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(interrupt_window_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(
        handler.add_handler(
            interrupt_window_handler::handler_delegate_t::create<test_handler>()
        )
    );

    handler.dump_log();
}

TEST_CASE("enable/disable")
{
    setup_eapis_test_support();
    using namespace vmcs_n::primary_processor_based_vm_execution_controls;

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    handler.enable_exiting();
    CHECK(interrupt_window_exiting::is_enabled());

    handler.disable_exiting();
    CHECK(interrupt_window_exiting::is_disabled());
}

void
reset_window()
{
    using namespace vmcs_n;

    guest_rflags::interrupt_enable_flag::enable();
    guest_interruptibility_state::blocking_by_sti::disable();
    guest_interruptibility_state::blocking_by_mov_ss::disable();

    guest_activity_state::set(guest_activity_state::active);
}

TEST_CASE("is_open")
{
    using namespace vmcs_n;

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    reset_window();
    guest_rflags::interrupt_enable_flag::disable();
    CHECK(handler.is_open() == false);

    reset_window();
    guest_interruptibility_state::blocking_by_sti::enable();
    CHECK(handler.is_open() == false);

    reset_window();
    guest_interruptibility_state::blocking_by_mov_ss::enable();
    CHECK(handler.is_open() == false);

    reset_window();
    guest_activity_state::set(guest_activity_state::shutdown);
    CHECK(handler.is_open() == false);

    reset_window();
    CHECK(handler.is_open() == true);
}

TEST_CASE("inject")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(handler.inject(0));
}

TEST_CASE("interrupt window exit")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        interrupt_window_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
}

TEST_CASE("interrupt window exit, no handler")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("interrupt window exit, ignore disable")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        interrupt_window_handler::handler_delegate_t::create<test_handler_ignore_disable>()
    );

    using namespace vmcs_n::primary_processor_based_vm_execution_controls;
    handler.enable_exiting();

    CHECK_NOTHROW(handler.handle(vmcs));
    CHECK(interrupt_window_exiting::is_enabled());
}

TEST_CASE("interrupt window exit, returns false")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = interrupt_window_handler(eapis, &g_eapis_vcpu_global_state);

    handler.add_handler(
        interrupt_window_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK_THROWS(handler.handle(vmcs));
}

#endif
