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

#include <hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <hve/arch/intel_x64/exit_handler/vmcall_interface.h>

#include <hve/arch/intel_x64/exit_handler/verifiers.h>
#include <hve/arch/intel_x64/exit_handler/rdmsr_verifiers.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::register_json_vmcall__rdmsr()
{
    m_json_commands["trap_on_rdmsr_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__trap_on_rdmsr_access(json_hex_or_dec<msr_type>(ijson, "msr"));
        this->json_success(ojson);
    };

    m_json_commands["pass_through_rdmsr_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__pass_through_rdmsr_access(json_hex_or_dec<msr_type>(ijson, "msr"));
        this->json_success(ojson);
    };

    m_json_commands["whitelist_rdmsr_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__whitelist_rdmsr_access(json_hex_or_dec_array<msr_type>(ijson, "msrs"));
        this->json_success(ojson);
    };

    m_json_commands["blacklist_rdmsr_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__blacklist_rdmsr_access(json_hex_or_dec_array<msr_type>(ijson, "msrs"));
        this->json_success(ojson);
    };

    m_json_commands["log_rdmsr_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__log_rdmsr_access(ijson.at("enabled"));
        this->json_success(ojson);
    };

    m_json_commands["clear_rdmsr_access_log"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__clear_rdmsr_access_log();
        this->json_success(ojson);
    };

    m_json_commands["rdmsr_access_log"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__rdmsr_access_log(ojson);
    };
}

void
exit_handler_intel_x64_eapis::handle_vmcall__rdmsr(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
        case eapis_fun__trap_on_rdmsr_access:
            handle_vmcall__trap_on_rdmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__trap_on_all_rdmsr_accesses:
            handle_vmcall__trap_on_all_rdmsr_accesses();
            break;

        case eapis_fun__pass_through_rdmsr_access:
            handle_vmcall__pass_through_rdmsr_access(gsl::narrow_cast<msr_type>(regs.r04));
            break;

        case eapis_fun__pass_through_all_rdmsr_accesses:
            handle_vmcall__pass_through_all_rdmsr_accesses();
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_rdmsr_access(
    msr_type msr)
{
    if (policy(trap_on_rdmsr_access)->verify(msr) != vmcall_verifier::allow) {
        policy(trap_on_rdmsr_access)->deny_vmcall();
    }

    m_vmcs_eapis->trap_on_rdmsr_access(msr);
    bfdebug_nhex(1, "trap_on_rdmsr_access", msr);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__trap_on_all_rdmsr_accesses()
{
    if (policy(trap_on_all_rdmsr_accesses)->verify() != vmcall_verifier::allow) {
        policy(trap_on_all_rdmsr_accesses)->deny_vmcall();
    }

    m_vmcs_eapis->trap_on_all_rdmsr_accesses();
    bfdebug_text(1, "trap_on_all_rdmsr_accesses", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_rdmsr_access(
    msr_type msr)
{
    if (policy(pass_through_rdmsr_access)->verify(msr) != vmcall_verifier::allow) {
        policy(pass_through_rdmsr_access)->deny_vmcall();
    }

    m_vmcs_eapis->pass_through_rdmsr_access(msr);
    bfdebug_nhex(1, "pass_through_rdmsr_access", msr);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__pass_through_all_rdmsr_accesses()
{
    if (policy(pass_through_all_rdmsr_accesses)->verify() != vmcall_verifier::allow) {
        policy(pass_through_all_rdmsr_accesses)->deny_vmcall();
    }

    m_vmcs_eapis->pass_through_all_rdmsr_accesses();
    bfdebug_text(1, "pass_through_all_rdmsr_accesses", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__whitelist_rdmsr_access(
    msr_list_type msrs)
{
    if (policy(whitelist_rdmsr_access)->verify(msrs) != vmcall_verifier::allow) {
        policy(whitelist_rdmsr_access)->deny_vmcall();
    }

    m_vmcs_eapis->whitelist_rdmsr_access(msrs);

    bfdebug_info(1, "whitelist_rdmsr_access");
    for (auto msr : msrs) {
        bfdebug_subnhex(1, "msr", msr);
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__blacklist_rdmsr_access(
    msr_list_type msrs)
{
    if (policy(blacklist_rdmsr_access)->verify(msrs) != vmcall_verifier::allow) {
        policy(blacklist_rdmsr_access)->deny_vmcall();
    }

    m_vmcs_eapis->blacklist_rdmsr_access(msrs);

    bfdebug_info(1, "blacklist_rdmsr_access");
    for (auto msr : msrs) {
        bfdebug_subnhex(1, "msr", msr);
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_rdmsr_access(
    bool enabled)
{
    if (policy(log_rdmsr_access)->verify(enabled) != vmcall_verifier::allow) {
        policy(log_rdmsr_access)->deny_vmcall();
    }

    log_rdmsr_access(enabled);
    bfdebug_bool(1, "log_rdmsr_access", enabled);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_rdmsr_access_log()
{
    if (policy(clear_rdmsr_access_log)->verify() != vmcall_verifier::allow) {
        policy(clear_rdmsr_access_log)->deny_vmcall();
    }

    clear_rdmsr_access_log();
    bfdebug_text(1, "clear_rdmsr_access_log", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__rdmsr_access_log(
    json &ojson)
{
    if (policy(rdmsr_access_log)->verify() != vmcall_verifier::allow) {
        policy(rdmsr_access_log)->deny_vmcall();
    }

    for (auto pair : m_rdmsr_access_log) {
        ojson[bfn::to_string(pair.first, 16)] = pair.second;
    }

    bfdebug_text(1, "dump rdmsr_access_log", "success");
}
