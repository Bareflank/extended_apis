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

#include "../../../../../include/support/arch/intel_x64/test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register unknown")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = 0xDEADBEEF;

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register enable io bitmaps allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__enable_io_bitmaps;

    g_enable_io_bitmaps = false;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register enable io bitmaps logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__enable_io_bitmaps;

    g_enable_io_bitmaps = false;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register enable io bitmaps denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__enable_io_bitmaps;

    g_enable_io_bitmaps = false;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register disable io bitmaps allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__disable_io_bitmaps;

    g_enable_io_bitmaps = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register disable io bitmaps logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__disable_io_bitmaps;

    g_enable_io_bitmaps = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(!g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register disable io bitmaps denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__disable_io_bitmaps;

    g_enable_io_bitmaps = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on all io accesses allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on all io accesses logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register trap on all io accesses denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through all io accesses allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through all io accesses logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: register pass through all io accesses denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_registers(regs));
    CHECK(g_port == 0);
    CHECK(ehlr->m_denials.empty());
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json enable io bitmaps missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_io_bitmaps"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json enable io bitmaps invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "enable_io_bitmaps"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json enable io bitmaps allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "enable_io_bitmaps"}, {"enabled", true}};
    json ijson2 = {{"command", "enable_io_bitmaps"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_enable_io_bitmaps = false;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_enable_io_bitmaps);

    g_enable_io_bitmaps = true;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(!g_enable_io_bitmaps);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json enable io bitmaps logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "enable_io_bitmaps"}, {"enabled", true}};
    json ijson2 = {{"command", "enable_io_bitmaps"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_enable_io_bitmaps = false;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.size() == 1);

    g_enable_io_bitmaps = true;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(!g_enable_io_bitmaps);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json enable io bitmaps denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "enable_io_bitmaps"}, {"enabled", true}};
    json ijson2 = {{"command", "enable_io_bitmaps"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_enable_io_bitmaps = false;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(!g_enable_io_bitmaps);

    g_enable_io_bitmaps = true;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_enable_io_bitmaps);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json trap on io access missing port")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "trap_on_io_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json trap on io access invalid port")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_io_access"}, {"port", "bad port"}};
    json ijson2 = {{"command", "trap_on_io_access"}, {"port_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json trap on io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json trap on io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json trap on io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json pass through io access missing port")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "pass_through_io_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json pass through io access invalid port")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_io_access"}, {"port", "bad port"}};
    json ijson2 = {{"command", "pass_through_io_access"}, {"port_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json pass through io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json pass through io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json pass through io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"command", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json whitelist io access missing ports")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "whitelist_io_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json whitelist io access invalid ports")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_io_access"}, {"ports", "bad port"}};
    json ijson2 = {{"command", "whitelist_io_access"}, {"ports_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json whitelist io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json whitelist io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json whitelist io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json blacklist io access missing ports")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "blacklist_io_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json blacklist io access invalid ports")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_io_access"}, {"ports", "bad port"}};
    json ijson2 = {{"command", "blacklist_io_access"}, {"ports_hex", 10}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json blacklist io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json blacklist io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 1);

    g_port = 0;
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(g_port == 42);
    CHECK(ehlr->m_denials.size() == 2);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json blacklist io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"command", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"command", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);

    g_port = 0;
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(g_port == 0);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json log io access missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_io_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json log io access invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_io_access"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json log io access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json log io access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json log io access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json clear io access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json clear io access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json clear io access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json io access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x000000000000002A\":42}");
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json io access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x000000000000002A\":42}");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_io_instruction_vmcall: json io access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "io_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "{\"0x000000000000002A\":42}");
}

#endif
