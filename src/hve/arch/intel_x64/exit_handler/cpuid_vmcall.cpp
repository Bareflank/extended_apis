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

#include <bfsdk/include/bfjson.h>
#include <bfsdk/include/bfstring.h>

#include <hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <hve/arch/intel_x64/exit_handler/vmcall_interface.h>
#include <hve/arch/intel_x64/exit_handler/verifiers.h>
#include <hve/arch/intel_x64/exit_handler/cpuid_verifiers.h>


void
exit_handler_intel_x64_eapis::register_json_vmcall__cpuid()
{
    m_json_commands["emulate_cpuid"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__emulate_cpuid(json_hex_or_dec<cpuid_type>(ijson, "leaf"),
                                           json_hex_or_dec<cpuid_type>(ijson, "subleaf"),
                                           ijson.at("eax"), ijson.at("ebx"), ijson.at("ecx"), ijson.at("edx"));
        this->json_success(ojson);
    };

    m_json_commands["reset_cpuid_leaf"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__reset_cpuid_leaf(json_hex_or_dec<cpuid_type>(ijson, "leaf"),
                                              json_hex_or_dec<cpuid_type>(ijson, "subleaf"));
        this->json_success(ojson);
    };

    m_json_commands["reset_cpuid_all"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__reset_cpuid_all();
        this->json_success(ojson);
    };

    m_json_commands["log_cpuid_access"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__log_cpuid_access(ijson.at("enabled"));
        this->json_success(ojson);
    };

    m_json_commands["clear_cpuid_access_log"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__clear_cpuid_access_log();
        this->json_success(ojson);
    };

    m_json_commands["cpuid_access_log"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__cpuid_access_log(ojson);
    };

    m_json_commands["dump_cpuid_emulations_log"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__dump_cpuid_emulations_log(ojson);
    };
}

uint64_t
exit_handler_intel_x64_eapis::create_key(
    cpuid_key_type leaf, cpuid_key_type subleaf)
{
    return (leaf << 32) | subleaf;
}

uint64_t
exit_handler_intel_x64_eapis::parse_emulate_cpuid_string(
    std::string reg_string, cpuid_key_type machine_reg)
{
    cpuid_key_type defined_mask = 0;
    cpuid_key_type passthru_mask = 0;
    cpuid_key_type bit_val = 1U << 31;

    /* For every "bit" in the register string, evaluate if the bit is defined
     * as 0, 1, or -. If it is 0, do nothing. If it is 1, set that bit in the
     * defined mask. If it is a - (passthru bit), set that bit in the passthru
     * mask. */
    for (auto bit : reg_string) {
        if (bit == '1') {
            defined_mask += bit_val;
        }
        else if (bit == '-') {
            passthru_mask += bit_val;
        }
        bit_val >>= 1;
    }

    /* Currently, all passthru characters, '-', are set to 1 in the passthru
     * mask. Use the bitwise '&' operator with the actual machine register
     * value to turn off any bits incorrectly set to 1. */
    passthru_mask = passthru_mask & machine_reg;
    /* The defined mask only contains bits explicitely enabled in the register
     * string. Use the bitwise '|' operator with the new passthru mask to
     * also enable bits set in the machine register and labeled as passthru in
     * the register string. */
    defined_mask = defined_mask | passthru_mask;
    return defined_mask;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__emulate_cpuid(
    cpuid_type leaf, cpuid_type subleaf,
    std::string eax, std::string ebx, std::string ecx, std::string edx)
{
    if (policy(emulate_cpuid)->verify(leaf, subleaf, eax, ebx, ecx, edx) != vmcall_verifier::allow) {
        policy(emulate_cpuid)->deny_vmcall();
    }

    auto machine_regs = x64::cpuid::get(leaf, 0, subleaf, 0);
    cpuid_key_type eax_val = parse_emulate_cpuid_string(eax, machine_regs.rax);
    cpuid_key_type ebx_val = parse_emulate_cpuid_string(ebx, machine_regs.rbx);
    cpuid_key_type ecx_val = parse_emulate_cpuid_string(ecx, machine_regs.rcx);
    cpuid_key_type edx_val = parse_emulate_cpuid_string(edx, machine_regs.rdx);

    cpuid_key_type key = create_key(leaf, subleaf);
    m_cpuid_emu_map[key] = { eax_val, ebx_val, ecx_val, edx_val };

    bfdebug_info(1, "emulate_cpuid");
    bfdebug_subnhex(1, "leaf", leaf);
    bfdebug_subnhex(1, "subleaf", subleaf);
    bfdebug_subnhex(1, "eax", eax_val);
    bfdebug_subnhex(1, "ebx", ebx_val);
    bfdebug_subnhex(1, "ecx", ecx_val);
    bfdebug_subnhex(1, "edx", edx_val);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__reset_cpuid_leaf(
    cpuid_type leaf, cpuid_type subleaf)
{
    if (policy(reset_cpuid_leaf)->verify(leaf, subleaf) != vmcall_verifier::allow) {
        policy(reset_cpuid_leaf)->deny_vmcall();
    }

    cpuid_key_type key = create_key(leaf, subleaf);
    m_cpuid_emu_map.erase(key);

    bfdebug_info(1, "reset_cpuid_leaf");
    bfdebug_subnhex(1, "leaf", leaf);
    bfdebug_subnhex(1, "subleaf", subleaf);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__reset_cpuid_all()
{
    if (policy(reset_cpuid_all)->verify() != vmcall_verifier::allow) {
        policy(reset_cpuid_all)->deny_vmcall();
    }

    m_cpuid_emu_map.clear();

    bfdebug_text(1, "reset_cpuid_all", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__log_cpuid_access(
    bool enabled)
{
    if (policy(log_cpuid_access)->verify(enabled) != vmcall_verifier::allow) {
        policy(log_cpuid_access)->deny_vmcall();
    }

    log_cpuid_access(enabled);

    bfdebug_bool(1, "log_cpuid_access", enabled);
}

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_cpuid_access_log()
{
    if (policy(clear_cpuid_access_log)->verify() != vmcall_verifier::allow) {
        policy(clear_cpuid_access_log)->deny_vmcall();
    }

    clear_cpuid_access_log();

    bfdebug_text(1, "clear_cpuid_access_log", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__cpuid_access_log(
    json &ojson)
{
    if (policy(cpuid_access_log)->verify() != vmcall_verifier::allow) {
        policy(cpuid_access_log)->deny_vmcall();
    }

    for (auto pair : m_cpuid_access_log) {
        ojson[bfn::to_string(pair.first, 16)] = pair.second;
    }

    bfdebug_text(1, "dump cpuid_access_log", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__dump_cpuid_emulations_log(
    json &ojson)
{
    if (policy(dump_cpuid_emulations_log)->verify() != vmcall_verifier::allow) {
        policy(dump_cpuid_emulations_log)->deny_vmcall();
    }

    for (auto pair : m_cpuid_emu_map) {
        ojson[bfn::to_string(pair.first, 16)] = {
            pair.second.rax, pair.second.rbx, pair.second.rcx, pair.second.rdx
        };
    }

    bfdebug_text(1, "dump cpuid_emulations_log", "success");
}
