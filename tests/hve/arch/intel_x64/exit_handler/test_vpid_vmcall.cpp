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

using namespace x64;
namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;


TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = 0xDEADBEEF;

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register enable vpid allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_vpid);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register enable vpid logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_vpid);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register enable vpid denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_vpid);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register disable vpid allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_vpid);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register disable vpid logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_vpid);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: register disable vpid denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_vpid);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: json vpid enable vpid missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_vpid"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: json vpid enable vpid invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_vpid"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: json vpid enable vpid allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(!g_enable_vpid);
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: json vpid enable vpid logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
    CHECK(!g_enable_vpid);
}

TEST_CASE("exit_handler_intel_x64_eapis_vpid_vmcall: json vpid enable vpid denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_enable_vpid);
}

#endif
