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

#include <test_support.h>
#include <catch/catch.hpp>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: invalid cr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 5);
    auto ehlr = setup_ehlr(vmcs);

    CHECK_THROWS(ehlr->dispatch());
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr0")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 0);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(guest_cr0::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr3")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 3);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(guest_cr3::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov from cr3")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 19);
    auto ehlr = setup_ehlr(vmcs);

    guest_cr3::set(42ULL);

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(g_state_save.rax == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr4")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 4);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(guest_cr4::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov to cr8")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 8);
    auto ehlr = setup_ehlr(vmcs);

    g_state_save.rax = 42ULL;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(cr8::get() == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: mov from cr8")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::control_register_accesses, 24);
    auto ehlr = setup_ehlr(vmcs);

    cr8::set(42ULL);

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(g_state_save.rax == 42ULL);
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: get_gpr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, 0);
    auto ehlr = setup_ehlr(vmcs);

    using namespace exit_qualification;
    using namespace control_register_access;

    CHECK(g_state_save.rax == ehlr->get_gpr(general_purpose_register::rax));
    CHECK(g_state_save.rbx == ehlr->get_gpr(general_purpose_register::rbx));
    CHECK(g_state_save.rcx == ehlr->get_gpr(general_purpose_register::rcx));
    CHECK(g_state_save.rdx == ehlr->get_gpr(general_purpose_register::rdx));
    CHECK(g_state_save.rsp == ehlr->get_gpr(general_purpose_register::rsp));
    CHECK(g_state_save.rbp == ehlr->get_gpr(general_purpose_register::rbp));
    CHECK(g_state_save.rsi == ehlr->get_gpr(general_purpose_register::rsi));
    CHECK(g_state_save.rdi == ehlr->get_gpr(general_purpose_register::rdi));
    CHECK(g_state_save.r08 == ehlr->get_gpr(general_purpose_register::r8));
    CHECK(g_state_save.r09 == ehlr->get_gpr(general_purpose_register::r9));
    CHECK(g_state_save.r10 == ehlr->get_gpr(general_purpose_register::r10));
    CHECK(g_state_save.r11 == ehlr->get_gpr(general_purpose_register::r11));
    CHECK(g_state_save.r12 == ehlr->get_gpr(general_purpose_register::r12));
    CHECK(g_state_save.r13 == ehlr->get_gpr(general_purpose_register::r13));
    CHECK(g_state_save.r14 == ehlr->get_gpr(general_purpose_register::r14));
    CHECK(g_state_save.r15 == ehlr->get_gpr(general_purpose_register::r15));

    CHECK_THROWS(ehlr->get_gpr(0x1000));
}

TEST_CASE("exit_handler_intel_x64_eapis_cr_emulation: set_gpr")
{
    MockRepository mocks;

    auto vmcs = setup_vmcs(mocks, 0);
    auto ehlr = setup_ehlr(vmcs);

    using namespace exit_qualification;
    using namespace control_register_access;

    ehlr->set_gpr(general_purpose_register::rax, 42ULL);
    ehlr->set_gpr(general_purpose_register::rbx, 42ULL);
    ehlr->set_gpr(general_purpose_register::rcx, 42ULL);
    ehlr->set_gpr(general_purpose_register::rdx, 42ULL);
    ehlr->set_gpr(general_purpose_register::rsp, 42ULL);
    ehlr->set_gpr(general_purpose_register::rbp, 42ULL);
    ehlr->set_gpr(general_purpose_register::rsi, 42ULL);
    ehlr->set_gpr(general_purpose_register::rdi, 42ULL);
    ehlr->set_gpr(general_purpose_register::r8, 42ULL);
    ehlr->set_gpr(general_purpose_register::r9, 42ULL);
    ehlr->set_gpr(general_purpose_register::r10, 42ULL);
    ehlr->set_gpr(general_purpose_register::r11, 42ULL);
    ehlr->set_gpr(general_purpose_register::r12, 42ULL);
    ehlr->set_gpr(general_purpose_register::r13, 42ULL);
    ehlr->set_gpr(general_purpose_register::r14, 42ULL);
    ehlr->set_gpr(general_purpose_register::r15, 42ULL);

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
