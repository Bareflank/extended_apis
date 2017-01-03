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

#include <to_string.h>

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>
#include <exit_handler/exit_handler_intel_x64_eapis_io_instruction_verifiers.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__io_instruction(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
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

bool
exit_handler_intel_x64_eapis::handle_vmcall_json__io_instruction(
    const json &ijson, json &ojson)
{
    auto set = ijson.value("set", std::string());

    if (!set.empty())
    {
        if (set == "trap_on_io_access")
        {
            handle_vmcall__trap_on_io_access(json_hex_or_dec<port_type>(ijson, "port"));
            ojson = {"success"};
            return true;
        }

        if (set == "pass_through_io_access")
        {
            handle_vmcall__pass_through_io_access(json_hex_or_dec<port_type>(ijson, "port"));
            ojson = {"success"};
            return true;
        }

        if (set == "whitelist_io_access")
        {
            handle_vmcall__whitelist_io_access(json_hex_or_dec_array<port_type>(ijson, "ports"));
            ojson = {"success"};
            return true;
        }

        if (set == "blacklist_io_access")
        {
            handle_vmcall__blacklist_io_access(json_hex_or_dec_array<port_type>(ijson, "ports"));
            ojson = {"success"};
            return true;
        }

        if (set == "log_io_access")
        {
            handle_vmcall__log_io_access(ijson.at("enabled"));
            ojson = {"success"};
            return true;
        }
    }

    auto run = ijson.value("run", std::string());

    if (!run.empty())
    {
        if (run == "clear_io_access_log")
        {
            handle_vmcall__clear_io_access_log();
            ojson = {"success"};
            return true;
        }
    }

    auto get = ijson.value("get", std::string());

    if (!get.empty())
    {
        if (get == "io_access_log")
        {
            handle_vmcall__io_access_log(ojson);
            return true;
        }
    }

    return false;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_io_access(
    port_type port)
{
    if (policy(trap_on_io_access)->verify(port) != vmcall_verifier::allow)
        policy(trap_on_io_access)->deny_vmcall();

    eapis_vmcs()->trap_on_io_access(port);
    bfdebug << "trap_on_io_access: " << std::hex << std::uppercase << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_io_accesses()
{
    if (policy(trap_on_all_io_accesses)->verify() != vmcall_verifier::allow)
        policy(trap_on_all_io_accesses)->deny_vmcall();

    eapis_vmcs()->trap_on_all_io_accesses();
    bfdebug << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_io_access(
    port_type port)
{
    if (policy(pass_through_io_access)->verify(port) != vmcall_verifier::allow)
        policy(pass_through_io_access)->deny_vmcall();

    eapis_vmcs()->pass_through_io_access(port);
    bfdebug << "pass_through_io_access: " << std::hex << std::uppercase << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_io_accesses()
{
    if (policy(pass_through_all_io_accesses)->verify() != vmcall_verifier::allow)
        policy(pass_through_all_io_accesses)->deny_vmcall();

    eapis_vmcs()->pass_through_all_io_accesses();
    bfdebug << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_io_access(
    const port_list_type &ports)
{
    if (policy(whitelist_io_access)->verify(ports) != vmcall_verifier::allow)
        policy(whitelist_io_access)->deny_vmcall();

    eapis_vmcs()->whitelist_io_access(ports);

    bfdebug << "whitelist_io_access: " << bfendl;
    for (auto port : ports)
        bfdebug << "  - " << std::hex << std::uppercase << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_io_access(
    const port_list_type &ports)
{
    if (policy(blacklist_io_access)->verify(ports) != vmcall_verifier::allow)
        policy(blacklist_io_access)->deny_vmcall();

    eapis_vmcs()->blacklist_io_access(ports);

    bfdebug << "blacklist_io_access: " << bfendl;
    for (auto port : ports)
        bfdebug << "  - " << std::hex << std::uppercase << "0x" << port << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_io_access(
    bool enabled)
{
    if (policy(log_io_access)->verify(enabled) != vmcall_verifier::allow)
        policy(log_io_access)->deny_vmcall();

    log_io_access(enabled);
    bfdebug << "log_io_access: " << std::boolalpha << enabled << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_io_access_log()
{
    if (policy(clear_io_access_log)->verify() != vmcall_verifier::allow)
        policy(clear_io_access_log)->deny_vmcall();

    clear_io_access_log();
    bfdebug << "clear_io_access_log: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__io_access_log(json &ojson)
{
    if (policy(io_access_log)->verify() != vmcall_verifier::allow)
        policy(io_access_log)->deny_vmcall();

    for (auto pair : m_io_access_log)
        ojson[bfn::to_string(pair.first, 16)] = pair.second;

    bfdebug << "dump io_access_log: success" << bfendl;
}
