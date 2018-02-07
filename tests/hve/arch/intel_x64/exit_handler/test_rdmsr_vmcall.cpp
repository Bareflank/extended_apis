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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = 0xDEADBEEF;

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on all rdmsr accesses allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on all rdmsr accesses logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register trap on all rdmsr accesses denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__trap_on_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_rdmsr_access;
    regs.r04 = 42;

    g_rdmsr = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through all rdmsr accesses allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through all rdmsr accesses logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: register pass through all rdmsr accesses denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__rdmsr;
    regs.r03 = eapis_fun__pass_through_all_rdmsr_accesses;

    g_rdmsr = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_rdmsr == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json trap on rdmsr access missing msr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "trap_on_rdmsr_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json trap on rdmsr access invalid msr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_rdmsr_access"}, {"msr", "bad msr"}};
    json ijson2 = {{"command", "trap_on_rdmsr_access"}, {"msr_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json trap on rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "trap_on_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json trap on rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "trap_on_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json trap on rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "trap_on_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json pass through rdmsr access missing rdmsr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "pass_through_rdmsr_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json pass through rdmsr access invalid msr")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_rdmsr_access"}, {"msr", "bad msr"}};
    json ijson2 = {{"command", "pass_through_rdmsr_access"}, {"msr_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json pass through rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "pass_through_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json pass through rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "pass_through_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json pass through rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_rdmsr_access"}, {"msr", 42}};
    json ijson2 = {{"command", "pass_through_rdmsr_access"}, {"msr_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json whitelist rdmsr access missing rdmsrs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "whitelist_rdmsr_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json whitelist rdmsr access invalid msrs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_rdmsr_access"}, {"msrs", "bad msr"}};
    json ijson2 = {{"command", "whitelist_rdmsr_access"}, {"msrs_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json whitelist rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "whitelist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json whitelist rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "whitelist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json whitelist rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "whitelist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json blacklist rdmsr access missing rdmsrs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "blacklist_rdmsr_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json blacklist rdmsr access invalid msrs")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_rdmsr_access"}, {"msrs", "bad msr"}};
    json ijson2 = {{"command", "blacklist_rdmsr_access"}, {"msrs_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json blacklist rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "blacklist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json blacklist rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "blacklist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_rdmsr = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_rdmsr == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json blacklist rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_rdmsr_access"}, {"msrs", {42}}};
    json ijson2 = {{"command", "blacklist_rdmsr_access"}, {"msrs_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);

    g_rdmsr = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_rdmsr == 0);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json log rdmsr access missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_rdmsr_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json log rdmsr access invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_rdmsr_access"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json log rdmsr access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_rdmsr_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json log rdmsr access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_rdmsr_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json log rdmsr access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_rdmsr_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json clear rdmsr access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json clear rdmsr access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json clear rdmsr access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json rdmsr access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_rdmsr_access_log[42] = 42;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x000000000000002A\":42}");
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json rdmsr access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();
    ehlr->m_rdmsr_access_log[42] = 42;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x000000000000002A\":42}");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_rdmsr_vmcall: json rdmsr access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "rdmsr_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_rdmsr_access_log[42] = 42;

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "{\"0x000000000000002A\":42}");
}

#endif
