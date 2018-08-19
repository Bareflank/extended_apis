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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>
#include <hve/arch/intel_x64/vmexit/control_register.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return false;
}

bool
test_handler_ignore_write(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_write = true;
    return false;
}

bool
test_handler_ignore_advance(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_advance = true;
    return false;
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(control_register_handler(eapis));
}

TEST_CASE("debugging enabled")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    CHECK_NOTHROW(handler.enable_log());
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    CHECK_NOTHROW(
        handler.add_wrcr0_handler(
            control_register_handler::handler_delegate_t::create<test_handler>()
        )
    );

    CHECK_NOTHROW(
        handler.add_rdcr3_handler(
            control_register_handler::handler_delegate_t::create<test_handler>()
        )
    );

    CHECK_NOTHROW(
        handler.add_wrcr3_handler(
            control_register_handler::handler_delegate_t::create<test_handler>()
        )
    );

    CHECK_NOTHROW(
        handler.add_wrcr4_handler(
            control_register_handler::handler_delegate_t::create<test_handler>()
        )
    );
}

TEST_CASE("enable exiting")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    CHECK_NOTHROW(
        handler.enable_wrcr0_exiting(0xFFFFFFFFFFFFFFFF, 0)
    );

    CHECK_NOTHROW(
        handler.enable_wrcr4_exiting(0xFFFFFFFFFFFFFFFF, 0)
    );

    CHECK_NOTHROW(handler.enable_rdcr3_exiting());
    CHECK_NOTHROW(handler.enable_wrcr3_exiting());
}

bfvmm::intel_x64::vmcs *
setup_vmcs(MockRepository &mocks)
{
    using namespace bfvmm::intel_x64;
    auto vmcs = mocks.Mock<bfvmm::intel_x64::vmcs>();

    mocks.OnCall(vmcs, vmcs::launch);
    mocks.OnCall(vmcs, vmcs::resume);
    mocks.OnCall(vmcs, vmcs::promote);
    mocks.OnCall(vmcs, vmcs::load);

    mocks.OnCall(vmcs, vmcs::save_state).Return(
        &g_save_state
    );

    g_save_state.rax = 42;

    return vmcs;
}

TEST_CASE("wrcr0 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr0::get() == 42);
    CHECK(vmcs_n::cr0_read_shadow::get() == 42);

    handler.dump_log();
}

TEST_CASE("wrcr0 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr0::get() != 42);
    CHECK(vmcs_n::cr0_read_shadow::get() != 42);
}

TEST_CASE("wrcr0 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr0::get() == 42);
    CHECK(vmcs_n::cr0_read_shadow::get() == 42);
}

TEST_CASE("wrcr3 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr3::get() == 42);

    handler.dump_log();
}

TEST_CASE("wrcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr3::get() != 42);
}

TEST_CASE("wrcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr3::get() == 42);
}

TEST_CASE("rdcr3 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    g_save_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 42);

    handler.dump_log();
}

TEST_CASE("rdcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    g_save_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax != 42);
}

TEST_CASE("rdcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    g_save_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 42);
}

TEST_CASE("invalid cr3 access")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000023ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("wrcr4 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr4::get() == 0x202a);
    CHECK(vmcs_n::cr4_read_shadow::get() == 42);

    handler.dump_log();
}

TEST_CASE("wrcr4 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr4::get() != 42);
    CHECK(vmcs_n::cr4_read_shadow::get() != 42);
}

TEST_CASE("wrcr4 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr4::get() == 0x202a);
    CHECK(vmcs_n::cr4_read_shadow::get() == 42);
}

TEST_CASE("invalid cr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x000000000000000AULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

#endif
