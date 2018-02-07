//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
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

namespace exit_handler_eapis = eapis::hve::intel_x64::exit_handler;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid missing args")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string valid = "00000000000000000000000000001000";

    json ijson1 = {{"command", "emulate_cpuid"}};
    json ijson2 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", valid}, {"ebx", valid}
    };
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid invalid args")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string valid = "00000000000000000000000000001000";

    json ijson1 = {{"command", "emulate_cpuid"}, {"leaf", "bad leaf"}, {"subleaf", "bad subleaf"},
        {"eax", valid}, {"ebx", valid}, {"ecx", valid}, {"edx", valid}
    };
    json ijson2 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", 8}, {"ebx", 8}, {"ecx", 8}, {"edx", 8}
    };
    json ijson3 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"rax", valid}, {"rbx", valid}, {"rcx", valid}, {"rdx", valid}
    };
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson3, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid invalid string")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string long_string = "0000000000000000000000000000001000";
    std::string short_string =                        "0000001000";
    std::string unknown_chars = "00000000000000000000000000001jwz";
    std::string valid =         "00000000000000000000000000001000";

    json ijson1 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", long_string}, {"ebx", long_string}, {"ecx", long_string}, {"edx", long_string}
    };
    json ijson2 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", short_string}, {"ebx", short_string}, {"ecx", short_string}, {"edx", short_string}
    };
    json ijson3 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", unknown_chars}, {"ebx", unknown_chars}, {"ecx", unknown_chars}, {"edx", unknown_chars}
    };
    json ijson4 = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", valid}, {"ebx", valid}, {"ecx", valid}, {"edx", valid}
    };
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson1, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson2, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson3, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson4, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) != ehlr->m_cpuid_emu_map.end());
    CHECK(ehlr->m_cpuid_emu_map[0].rax == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rbx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rcx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rdx == 8);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string valid =   "00000000000000000000000000001000";

    json ijson = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", valid}, {"ebx", valid}, {"ecx", valid}, {"edx", valid}
    };
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) != ehlr->m_cpuid_emu_map.end());
    CHECK(ehlr->m_cpuid_emu_map[0].rax == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rbx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rcx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rdx == 8);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string valid =   "00000000000000000000000000001000";

    json ijson = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", valid}, {"ebx", valid}, {"ecx", valid}, {"edx", valid}
    };
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) != ehlr->m_cpuid_emu_map.end());
    CHECK(ehlr->m_cpuid_emu_map[0].rax == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rbx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rcx == 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rdx == 8);
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json emulate cpuid denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    exit_handler_eapis::exit_handler::cpuid_type leaf = 0;
    exit_handler_eapis::exit_handler::cpuid_type subleaf = 0;
    std::string valid =   "00000000000000000000000000001000";

    json ijson = {{"command", "emulate_cpuid"}, {"leaf", leaf}, {"subleaf", subleaf},
        {"eax", valid}, {"ebx", valid}, {"ecx", valid}, {"edx", valid}
    };
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK(ehlr->m_cpuid_emu_map[0].rax != 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rbx != 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rcx != 8);
    CHECK(ehlr->m_cpuid_emu_map[0].rdx != 8);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid leaf missing args")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_leaf"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid leaf invalid args")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_leaf"}, {"leaf", "bad leaf"}, {"subleaf", "bad subleaf"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid leaf allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_leaf"}, {"leaf", 0}, {"subleaf", 0}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid leaf logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_leaf"}, {"leaf", 0}, {"subleaf", 0}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) == ehlr->m_cpuid_emu_map.end());
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid leaf denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_leaf"}, {"leaf", 0}, {"subleaf", 0}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.find(0) != ehlr->m_cpuid_emu_map.end());
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid all allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_all"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.empty());
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid all logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_all"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_cpuid_emu_map.empty());
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json reset cpuid all denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "reset_cpuid_all"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };
    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
    CHECK_FALSE(ehlr->m_cpuid_emu_map.empty());
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json log cpuid access missing enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_cpuid_access"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json log cpuid access invalid enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_cpuid_access"}, {"enabled", "not a bool"}};
    json ojson = {};

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json log cpuid access allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_cpuid_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json log cpuid access logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_cpuid_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json log cpuid access denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "log_cpuid_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json clear cpuid access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_cpuid_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json clear cpuid access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_cpuid_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "[\"success\"]");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json clear cpuid access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "clear_cpuid_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "[\"success\"]");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json cpuid access log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "cpuid_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_cpuid_access_log[0] = 8;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x0000000000000000\":8}");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json cpuid access log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "cpuid_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();
    ehlr->m_cpuid_access_log[0] = 8;

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x0000000000000000\":8}");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json cpuid access log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "cpuid_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_cpuid_access_log[0] = 8;

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "{\"0x0000000000000000\":8}");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json dump cpuid emulations log allowed")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_cpuid_emulations_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x0000000000000000\":[8,8,8,8]}");
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json dump cpuid emulations log logged")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_cpuid_emulations_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();
    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };

    CHECK_NOTHROW(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() == "{\"0x0000000000000000\":[8,8,8,8]}");
    CHECK(ehlr->m_denials.size() == 1);
}

TEST_CASE("eapis_exit_handler_cpuid_vmcall: json dump cpuid emulations log denied")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, 0x0);
    auto ehlr = setup_ehlr(vmcs);

    json ijson = {{"command", "dump_cpuid_emulations_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_cpuid_emu_map[0] = { 8, 8, 8, 8 };

    CHECK_THROWS(ehlr->handle_vmcall_data_string_json(ijson, ojson));
    CHECK(ojson.dump() != "{\"0x0000000000000000\":[8,8,8,8]}");
}

#endif
