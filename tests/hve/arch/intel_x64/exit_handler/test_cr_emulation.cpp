//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn   <quinnr@ainfosec.com>
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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

#include "../../../../../include/support/arch/intel_x64/test_support.h"

namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;
namespace reason = vmcs::exit_reason::basic_exit_reason;
namespace exit_qual = vmcs::exit_qualification;
namespace ctlreg_access = exit_qual::control_register_access;
namespace gpr = ctlreg_access::general_purpose_register;


TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: invalid cr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 5);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_NOTHROW(ehlr->dispatch());
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr0")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 0);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(vmcs::guest_cr0::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr3")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 3);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(vmcs::guest_cr3::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov from cr3")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 19);
    auto ehlr = setup_ehlr(vmcs);

    vmcs::guest_cr3::set(42ULL);

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(g_state_save.rax == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr4")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 4);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(vmcs::guest_cr4::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr8")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 8);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(intel::cr8::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov from cr8")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, reason::control_register_accesses, 24);
    auto ehlr = setup_ehlr(vmcs);

    intel::cr8::set(42ULL);

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(g_state_save.rax == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: get_gpr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, 0);
    auto ehlr = setup_ehlr(vmcs);

    CHECK(g_state_save.rax == ehlr->get_gpr(gpr::rax));
    CHECK(g_state_save.rbx == ehlr->get_gpr(gpr::rbx));
    CHECK(g_state_save.rcx == ehlr->get_gpr(gpr::rcx));
    CHECK(g_state_save.rdx == ehlr->get_gpr(gpr::rdx));
    CHECK(g_state_save.rsp == ehlr->get_gpr(gpr::rsp));
    CHECK(g_state_save.rbp == ehlr->get_gpr(gpr::rbp));
    CHECK(g_state_save.rsi == ehlr->get_gpr(gpr::rsi));
    CHECK(g_state_save.rdi == ehlr->get_gpr(gpr::rdi));
    CHECK(g_state_save.r08 == ehlr->get_gpr(gpr::r8));
    CHECK(g_state_save.r09 == ehlr->get_gpr(gpr::r9));
    CHECK(g_state_save.r10 == ehlr->get_gpr(gpr::r10));
    CHECK(g_state_save.r11 == ehlr->get_gpr(gpr::r11));
    CHECK(g_state_save.r12 == ehlr->get_gpr(gpr::r12));
    CHECK(g_state_save.r13 == ehlr->get_gpr(gpr::r13));
    CHECK(g_state_save.r14 == ehlr->get_gpr(gpr::r14));
    CHECK(g_state_save.r15 == ehlr->get_gpr(gpr::r15));

    CHECK_THROWS(ehlr->get_gpr(0x1000));
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: set_gpr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, 0);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->set_gpr(gpr::rax, 42ULL);
    ehlr->set_gpr(gpr::rbx, 42ULL);
    ehlr->set_gpr(gpr::rcx, 42ULL);
    ehlr->set_gpr(gpr::rdx, 42ULL);
    ehlr->set_gpr(gpr::rsp, 42ULL);
    ehlr->set_gpr(gpr::rbp, 42ULL);
    ehlr->set_gpr(gpr::rsi, 42ULL);
    ehlr->set_gpr(gpr::rdi, 42ULL);
    ehlr->set_gpr(gpr::r8, 42ULL);
    ehlr->set_gpr(gpr::r9, 42ULL);
    ehlr->set_gpr(gpr::r10, 42ULL);
    ehlr->set_gpr(gpr::r11, 42ULL);
    ehlr->set_gpr(gpr::r12, 42ULL);
    ehlr->set_gpr(gpr::r13, 42ULL);
    ehlr->set_gpr(gpr::r14, 42ULL);
    ehlr->set_gpr(gpr::r15, 42ULL);

    CHECK(g_state_save.rax == 42ULL);
    CHECK(g_state_save.rbx == 42ULL);
    CHECK(g_state_save.rcx == 42ULL);
    CHECK(g_state_save.rdx == 42ULL);
    CHECK(g_state_save.rsp == 42ULL);
    CHECK(g_state_save.rbp == 42ULL);
    CHECK(g_state_save.rsi == 42ULL);
    CHECK(g_state_save.rdi == 42ULL);
    CHECK(g_state_save.r08 == 42ULL);
    CHECK(g_state_save.r09 == 42ULL);
    CHECK(g_state_save.r10 == 42ULL);
    CHECK(g_state_save.r11 == 42ULL);
    CHECK(g_state_save.r12 == 42ULL);
    CHECK(g_state_save.r13 == 42ULL);
    CHECK(g_state_save.r14 == 42ULL);
    CHECK(g_state_save.r15 == 42ULL);

    CHECK_THROWS(ehlr->set_gpr(0x1000, 42ULL));
}

#endif
