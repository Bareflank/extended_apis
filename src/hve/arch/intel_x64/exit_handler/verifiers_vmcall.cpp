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

#include "../../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/vmcall_interface.h"

using namespace x64;
namespace intel = intel_x64;

void
exit_handler_intel_x64_eapis::register_json_vmcall__verifiers()
{
    m_json_commands["clear_denials"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__clear_denials();
        this->json_success(ojson);
    };

    m_json_commands["dump_policy"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__dump_policy(ojson);
    };

    m_json_commands["dump_denials"] = [&](const auto &, auto & ojson) {
        this->handle_vmcall__dump_denials(ojson);
    };
}

template <class T>
std::string get_typename(const T &t)
{ return typeid(t).name(); }

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_denials()
{
    if (policy(clear_denials)->verify() != vmcall_verifier::allow) {
        policy(clear_denials)->deny_vmcall();
    }

    this->clear_denials();
    bfdebug_text(1, "clear_denials", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__dump_policy(json &ojson)
{
    if (policy(dump_policy)->verify() != vmcall_verifier::allow) {
        policy(dump_policy)->deny_vmcall();
    }

    for (const auto &pair : m_verifiers) {
        ojson[get_typename(*pair.second)] = pair.second->to_string();
    }

    bfdebug_text(1, "dump_policy", "success");
}

void
exit_handler_intel_x64_eapis::handle_vmcall__dump_denials(json &ojson)
{
    if (policy(dump_denials)->verify() != vmcall_verifier::allow) {
        policy(dump_denials)->deny_vmcall();
    }

    for (const auto &str : m_denials) {
        ojson.push_back(str);
    }

    bfdebug_text(1, "dump_denials", "success");
}
