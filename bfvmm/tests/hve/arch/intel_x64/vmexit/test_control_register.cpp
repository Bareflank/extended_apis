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

    CHECK_NOTHROW(control_register_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

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
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    CHECK_NOTHROW(
        handler.enable_wrcr0_exiting(0xFFFFFFFFFFFFFFFF)
    );

    CHECK_NOTHROW(
        handler.enable_wrcr4_exiting(0xFFFFFFFFFFFFFFFF)
    );

    CHECK_NOTHROW(handler.enable_rdcr3_exiting());
    CHECK_NOTHROW(handler.enable_wrcr3_exiting());
}

TEST_CASE("wrcr0 log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("wrcr0 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr0::get() == 42);
    CHECK(vmcs_n::cr0_read_shadow::get() == 42);
}

TEST_CASE("wrcr0 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr0::set(0);
    vmcs_n::cr0_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr0::get() == 0);
    CHECK(vmcs_n::cr0_read_shadow::get() == 0);
}

TEST_CASE("wrcr0 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000000ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr0_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("cr0 mov_from_cr not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000010ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("cr0 clts not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000020ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("cr0 lmsw not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000030ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("wrcr3 log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("wrcr3 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr3::get() == 42);
}

TEST_CASE("wrcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr3::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr3::get() == 0);
}

TEST_CASE("wrcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000003ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("rdcr3 log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("rdcr3 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 42);
}

TEST_CASE("rdcr3 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 0;
    vmcs_n::guest_cr3::set(42);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rax == 0);
}

TEST_CASE("rdcr3 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000013ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_rdcr3_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("cr3 clts not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000023ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("cr3 lmsw not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000033ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("wrcr4 log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    handler.enable_log();

    CHECK(handler.handle(vmcs) == true);
    CHECK_NOTHROW(handler.dump_log());
}

TEST_CASE("wrcr4 exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr4::get() == 42);
    CHECK(vmcs_n::cr4_read_shadow::get() == 42);
}

TEST_CASE("wrcr4 exit, ignore write")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rax = 42;
    vmcs_n::guest_cr4::set(0);
    vmcs_n::cr4_read_shadow::set(0);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_write>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(vmcs_n::guest_cr4::get() == 0);
    CHECK(vmcs_n::cr4_read_shadow::get() == 0);
}

TEST_CASE("wrcr4 exit, ignore advance")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    g_save_state.rip = 0;

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000004ULL
    );

    ::intel_x64::vm::write(
        vmcs_n::vm_exit_instruction_length::addr, 42
    );

    handler.add_wrcr4_handler(
        control_register_handler::handler_delegate_t::create<test_handler_ignore_advance>()
    );

    CHECK(handler.handle(vmcs) == true);
    CHECK(g_save_state.rip == 0);
}

TEST_CASE("cr4 mov_from_cr not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000014ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("cr4 clts not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000024ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("cr4 lmsw not supported")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x0000000000000034ULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

TEST_CASE("invalid cr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks);
    auto eapis = setup_eapis(mocks);
    auto handler = control_register_handler(eapis, &g_eapis_vcpu_global_state);

    ::intel_x64::vm::write(
        vmcs_n::exit_qualification::addr,
        0x000000000000000AULL
    );

    CHECK_THROWS(handler.handle(vmcs));
}

#endif
