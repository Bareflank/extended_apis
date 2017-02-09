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
#include <exit_handler/exit_handler_intel_x64_eapis_wrmsr_verifiers.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::register_json_vmcall__wrmsr()
{
    m_json_commands["trap_on_wrmsr_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__trap_on_wrmsr_access(json_hex_or_dec<msr_type>(ijson, "msr"));
        this->json_success(ojson);
    };

    m_json_commands["pass_through_wrmsr_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__pass_through_wrmsr_access(json_hex_or_dec<msr_type>(ijson, "msr"));
        this->json_success(ojson);
    };

    m_json_commands["whitelist_wrmsr_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__whitelist_wrmsr_access(json_hex_or_dec_array<msr_type>(ijson, "msrs"));
        this->json_success(ojson);
    };

    m_json_commands["blacklist_wrmsr_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__blacklist_wrmsr_access(json_hex_or_dec_array<msr_type>(ijson, "msrs"));
        this->json_success(ojson);
    };

    m_json_commands["log_wrmsr_access"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__log_wrmsr_access(ijson.at("enabled"));
        this->json_success(ojson);
    };

    m_json_commands["clear_wrmsr_access_log"] = [&](const auto &, auto & ojson)
    {
        this->handle_vmcall__clear_wrmsr_access_log();
        this->json_success(ojson);
    };

    m_json_commands["wrmsr_access_log"] = [&](const auto &, auto & ojson)
    {
        this->handle_vmcall__wrmsr_access_log(ojson);
    };
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__wrmsr(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__trap_on_wrmsr_access:
            handle_vmcall__trap_on_wrmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_wrmsr_accesses:
            handle_vmcall__trap_on_all_wrmsr_accesses();
            break;

        case eapis_fun__pass_through_wrmsr_access:
            handle_vmcall__pass_through_wrmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_wrmsr_accesses:
            handle_vmcall__pass_through_all_wrmsr_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_wrmsr_access(
    msr_type msr)
{
    if (policy(trap_on_wrmsr_access)->verify(msr) != vmcall_verifier::allow)
        policy(trap_on_wrmsr_access)->deny_vmcall();

    m_vmcs_eapis->trap_on_wrmsr_access(msr);
    vmcall_debug << "trap_on_wrmsr_access: " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_wrmsr_accesses()
{
    if (policy(trap_on_all_wrmsr_accesses)->verify() != vmcall_verifier::allow)
        policy(trap_on_all_wrmsr_accesses)->deny_vmcall();

    m_vmcs_eapis->trap_on_all_wrmsr_accesses();
    vmcall_debug << "trap_on_all_wrmsr_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_wrmsr_access(
    msr_type msr)
{
    if (policy(pass_through_wrmsr_access)->verify(msr) != vmcall_verifier::allow)
        policy(pass_through_wrmsr_access)->deny_vmcall();

    m_vmcs_eapis->pass_through_wrmsr_access(msr);
    vmcall_debug << "pass_through_wrmsr_access: " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_wrmsr_accesses()
{
    if (policy(pass_through_all_wrmsr_accesses)->verify() != vmcall_verifier::allow)
        policy(pass_through_all_wrmsr_accesses)->deny_vmcall();

    m_vmcs_eapis->pass_through_all_wrmsr_accesses();
    vmcall_debug << "trap_on_all_io_accesses: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_wrmsr_access(
    msr_list_type msrs)
{
    if (policy(whitelist_wrmsr_access)->verify(msrs) != vmcall_verifier::allow)
        policy(whitelist_wrmsr_access)->deny_vmcall();

    m_vmcs_eapis->whitelist_wrmsr_access(msrs);

    vmcall_debug << "whitelist_wrmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_wrmsr_access(
    msr_list_type msrs)
{
    if (policy(blacklist_wrmsr_access)->verify(msrs) != vmcall_verifier::allow)
        policy(blacklist_wrmsr_access)->deny_vmcall();

    m_vmcs_eapis->blacklist_wrmsr_access(msrs);

    vmcall_debug << "blacklist_wrmsr_access: " << bfendl;
    for (auto msr : msrs)
        vmcall_debug << "  - " << std::hex << std::uppercase << "0x" << msr << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_wrmsr_access(
    bool enabled)
{
    if (policy(log_wrmsr_access)->verify(enabled) != vmcall_verifier::allow)
        policy(log_wrmsr_access)->deny_vmcall();

    log_wrmsr_access(enabled);
    vmcall_debug << "log_wrmsr_access: " << std::boolalpha << enabled << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_wrmsr_access_log()
{
    if (policy(clear_wrmsr_access_log)->verify() != vmcall_verifier::allow)
        policy(clear_wrmsr_access_log)->deny_vmcall();

    clear_wrmsr_access_log();
    vmcall_debug << "clear_wrmsr_access_log: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__wrmsr_access_log(
    json &ojson)
{
    if (policy(wrmsr_access_log)->verify() != vmcall_verifier::allow)
        policy(wrmsr_access_log)->deny_vmcall();

    for (auto pair : m_wrmsr_access_log)
        ojson[bfn::to_string(pair.first, 16)] = pair.second;

    vmcall_debug << "dump wrmsr_access_log: success" << bfendl;
}
