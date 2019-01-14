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
#include <hve/arch/intel_x64/vmexit/ept_violation.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, ept_violation_handler::info_t &info)
{
    bfignored(info);
    bfignored(vmcs);

    return true;
}

bool
test_handler_returns_false(
    gsl::not_null<vmcs_t *> vmcs, ept_violation_handler::info_t &info)
{
    bfignored(info);
    bfignored(vmcs);

    return false;
}

bool
test_handler_ignore_advance(
    gsl::not_null<vmcs_t *> vmcs, ept_violation_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_advance = true;
    return true;
}

TEST_CASE("constructor/destruction")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(ept_violation_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("add handlers")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(
        handler.add_read_handler(
            ept_violation_handler::handler_delegate_t::create<test_handler>()
        )
    );

    CHECK_NOTHROW(
        handler.add_write_handler(
            ept_violation_handler::handler_delegate_t::create<test_handler>()
        )
    );

    CHECK_NOTHROW(
        handler.add_execute_handler(
            ept_violation_handler::handler_delegate_t::create<test_handler>()
        )
    );
}

TEST_CASE("ept violation log")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 1
    );

    handler.add_read_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("ept read violation exit")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 1
    );

    handler.add_read_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
}

TEST_CASE("ept read violation exit, ignore advance")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 1
    );

    handler.add_read_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("ept read violation exit, no handler")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 1
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept read violation exit, returns false")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 1
    );

    handler.add_read_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept write violation exit")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 2
    );

    handler.add_write_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
}

TEST_CASE("ept write violation exit, ignore advance")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 2
    );

    handler.add_write_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("ept write violation exit, no handler")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 2
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept write violation exit, returns false")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 2
    );

    handler.add_write_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept execute violation exit")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 4
    );

    handler.add_execute_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
}

TEST_CASE("ept execute violation exit, ignore advance")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 4
    );

    handler.add_execute_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("ept execute violation exit, no handler")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 4
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept execute violation exit, returns false")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 4
    );

    handler.add_execute_handler(
        ept_violation_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("ept violation exit, invalid qualification")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = ept_violation_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr, 0xF00
    );

    CHECK_THROWS(handler.handle(vmcs));
}


#endif
