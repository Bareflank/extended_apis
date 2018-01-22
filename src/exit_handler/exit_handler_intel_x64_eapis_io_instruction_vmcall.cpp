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

#include <bfstring.h>

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>
#include <exit_handler/exit_handler_intel_x64_eapis_io_instruction_verifiers.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::register_json_vmcall__io_instruction()
{
    m_json_commands["enable_io_bitmaps"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__enable_io_bitmaps(ijson.at("enabled"));
        this->json_success(ojson);
    };

    m_json_commands["trap_on_io_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__trap_on_io_access(json_hex_or_dec<port_type>(ijson, "port"));
        this->json_success(ojson);
    };

    m_json_commands["pass_through_io_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__pass_through_io_access(json_hex_or_dec<port_type>(ijson, "port"));
        this->json_success(ojson);
    };

    m_json_commands["whitelist_io_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__whitelist_io_access(json_hex_or_dec_array<port_type>(ijson, "ports"));
        this->json_success(ojson);
    };

    m_json_commands["blacklist_io_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__blacklist_io_access(json_hex_or_dec_array<port_type>(ijson, "ports"));
        this->json_success(ojson);
    };

    m_json_commands["log_io_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__log_io_access(ijson.at("enabled"));
        this->json_success(ojson);
    };

    m_json_commands["clear_io_access_log"] = [&](const auto &, auto & ojson)
    {
        this->handle_vmcall__clear_io_access_log();
        this->json_success(ojson);
    };

    m_json_commands["io_access_log"] = [&](const auto &, auto & ojson)
    {
        this->handle_vmcall__io_access_log(ojson);
    };
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__io_instruction(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__enable_io_bitmaps:
            handle_vmcall__enable_io_bitmaps(true);
            break;

        case eapis_fun__disable_io_bitmaps:
            handle_vmcall__enable_io_bitmaps(false);
            break;

        case eapis_fun__trap_on_io_access:
            handle_vmcall__trap_on_io_access(gsl::narrow_cast<port_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_io_accesses:
            handle_vmcall__trap_on_all_io_accesses();
            break;

        case eapis_fun__pass_through_io_access:
            handle_vmcall__pass_through_io_access(gsl::narrow_cast<port_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_io_accesses:
            handle_vmcall__pass_through_all_io_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_io_bitmaps(
    bool enabled)
{
    if (policy(enable_io_bitmaps)->verify(enabled) != vmcall_verifier::allow)
        policy(enable_io_bitmaps)->deny_vmcall();

    if (enabled)
    {
        m_vmcs_eapis->enable_io_bitmaps();
        bfdebug_info(0, "enable_io_bitmaps: success");
    }
    else
    {
        m_vmcs_eapis->disable_io_bitmaps();
        bfdebug_info(0, "disable_io_bitmaps: success");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_io_access(
    port_type port)
{
    if (policy(trap_on_io_access)->verify(port) != vmcall_verifier::allow)
        policy(trap_on_io_access)->deny_vmcall();

    m_vmcs_eapis->trap_on_io_access(port);
    bfdebug_nhex(0, "trap_on_io_access", port);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_io_accesses()
{
    if (policy(trap_on_all_io_accesses)->verify() != vmcall_verifier::allow)
        policy(trap_on_all_io_accesses)->deny_vmcall();

    m_vmcs_eapis->trap_on_all_io_accesses();
    bfdebug_info(0, "trap_on_all_io_accesses: success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_io_access(
    port_type port)
{
    if (policy(pass_through_io_access)->verify(port) != vmcall_verifier::allow)
        policy(pass_through_io_access)->deny_vmcall();

    m_vmcs_eapis->pass_through_io_access(port);
    bfdebug_nhex(0, "pass_through_io_access: ", port);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_io_accesses()
{
    if (policy(pass_through_all_io_accesses)->verify() != vmcall_verifier::allow)
        policy(pass_through_all_io_accesses)->deny_vmcall();

    m_vmcs_eapis->pass_through_all_io_accesses();
    bfdebug_info(0, "trap_on_all_io_accesses: success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_io_access(
    const port_list_type &ports)
{
    if (policy(whitelist_io_access)->verify(ports) != vmcall_verifier::allow)
        policy(whitelist_io_access)->deny_vmcall();

    m_vmcs_eapis->whitelist_io_access(ports);

    bfdebug_info(0, "whitelist_io_access: ");
    for (auto port : ports)
        bfdebug_subnhex(0, nullptr, port);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_io_access(
    const port_list_type &ports)
{
    if (policy(blacklist_io_access)->verify(ports) != vmcall_verifier::allow)
        policy(blacklist_io_access)->deny_vmcall();

    m_vmcs_eapis->blacklist_io_access(ports);

    bfdebug_info(0, "blacklist_io_access: ");
    for (auto port : ports)
        bfdebug_subnhex(0, nullptr, port);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_io_access(
    bool enabled)
{
    if (policy(log_io_access)->verify(enabled) != vmcall_verifier::allow)
        policy(log_io_access)->deny_vmcall();

    log_io_access(enabled);
    bfdebug_bool(0, "log_io_access", enabled)
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_io_access_log()
{
    if (policy(clear_io_access_log)->verify() != vmcall_verifier::allow)
        policy(clear_io_access_log)->deny_vmcall();

    clear_io_access_log();
    bfdebug_info(0, "clear_io_access_log: success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__io_access_log(json &ojson)
{
    if (policy(io_access_log)->verify() != vmcall_verifier::allow)
        policy(io_access_log)->deny_vmcall();

    for (auto pair : m_io_access_log)
        ojson[bfn::to_string(pair.first, 16)] = pair.second;

    bfdebug_info(0, "dump io_access_log: success");
}
