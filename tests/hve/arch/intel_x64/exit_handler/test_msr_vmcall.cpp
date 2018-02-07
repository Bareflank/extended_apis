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

TEST_CASE("eapis_exit_handler_msr_vmcall: register unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = 0xDEADBEEF;

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register enable msr bitmap allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__enable_msr_bitmap;

    g_enable_msr_bitmap = false;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register enable msr bitmap logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__enable_msr_bitmap;

    g_enable_msr_bitmap = false;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register enable msr bitmap denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__enable_msr_bitmap;

    g_enable_msr_bitmap = false;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register disable msr bitmap allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__disable_msr_bitmap;

    g_enable_msr_bitmap = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register disable msr bitmap logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__disable_msr_bitmap;

    g_enable_msr_bitmap = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_msr_vmcall: register disable msr bitmap denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__msr;
    regs.r03 = eapis_fun__disable_msr_bitmap;

    g_enable_msr_bitmap = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_msr_bitmap);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_msr_vmcall: json enable msr bitmap missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_msr_bitmap"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_msr_vmcall: json enable msr bitmap invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_msr_bitmap"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_msr_vmcall: json enable msr bitmap allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_msr_bitmap"}, {"enabled", false}};
    json ojson = {};

    g_enable_msr_bitmap = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(!g_enable_msr_bitmap);
}

TEST_CASE("eapis_exit_handler_msr_vmcall: json enable msr bitmap logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_msr_bitmap"}, {"enabled", false}};
    json ojson = {};

    g_enable_msr_bitmap = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
    CHECK(!g_enable_msr_bitmap);
}

TEST_CASE("eapis_exit_handler_msr_vmcall: json enable msr bitmap denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_msr_bitmap"}, {"enabled", false}};
    json ojson = {};

    g_enable_msr_bitmap = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_enable_msr_bitmap);
}

#endif
