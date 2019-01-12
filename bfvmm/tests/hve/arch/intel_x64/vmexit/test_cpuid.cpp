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
#include <hve/arch/intel_x64/vmexit/cpuid.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);

    info.rax = 42;
    info.rbx = 42;
    info.rcx = 42;
    info.rdx = 42;

    return true;
}

bool
test_handler_returns_false(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return false;
}

bool
test_handler_ignore_write(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_write = true;
    return true;
}

bool
test_handler_ignore_advance(
    gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_advance = true;
    return true;
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(cpuid_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(
        handler.add_handler(
            42, cpuid_handler::handler_delegate_t::create<test_handler>()
        )
    );
}

TEST_CASE("cpuid log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;

    handler.add_handler(
        42, cpuid_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("cpuid exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    g_save_state.rbx = 0;
    g_save_state.rcx = 0;
    g_save_state.rdx = 0;

    handler.add_handler(
        42, cpuid_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 42);
    CHECK(g_save_state.rbx == 42);
    CHECK(g_save_state.rcx == 42);
    CHECK(g_save_state.rdx == 42);
}

TEST_CASE("cpuid exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    g_save_state.rbx = 0;
    g_save_state.rcx = 0;
    g_save_state.rdx = 0;

    handler.add_handler(
        42, cpuid_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 42);
    CHECK(g_save_state.rbx == 0);
    CHECK(g_save_state.rcx == 0);
    CHECK(g_save_state.rdx == 0);
}

TEST_CASE("cpuid exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;
    g_save_state.rax = 42;

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_handler(
        42, cpuid_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("cpuid exit, no handler")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 0;
    CHECK(handler.handle(vmcs) == false);
}

TEST_CASE("cpuid exit, returns false")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = cpuid_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;

    handler.add_handler(
        42, cpuid_handler::handler_delegate_t::create<test_handler_returns_false>()
    );

    CHECK(handler.handle(vmcs) == false);
}

#endif
