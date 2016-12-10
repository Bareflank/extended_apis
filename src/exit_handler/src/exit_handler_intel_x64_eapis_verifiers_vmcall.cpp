//
// Bareflank Hypervisor Examples
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

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

using namespace x64;
using namespace intel_x64;

bool
exit_handler_intel_x64_eapis::handle_vmcall_json__verifiers(
    const json &ijson, json &ojson)
{
    auto run = ijson.value("run", std::string());

    if (!run.empty())
    {
        if (run == "clear_denials")
        {
            handle_vmcall__clear_denials();
            ojson = {"success"};
            return true;
        }
    }

    auto dump = ijson.value("dump", std::string());

    if (!dump.empty())
    {
        if (dump == "policy")
        {
            handle_vmcall__dump_policy(ojson);
            return true;
        }

        if (dump == "denials")
        {
            handle_vmcall__dump_denials(ojson);
            return true;
        }
    }

    return false;
}

template <class T>
std::string get_typename(const T &t)
{ return typeid(t).name(); }

void
exit_handler_intel_x64_eapis::handle_vmcall__clear_denials()
{
    if (policy(clear_denials)->verify() != vmcall_verifier::allow)
        policy(clear_denials)->deny_vmcall();

    this->clear_denials();
    bfdebug << "clear_denials: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__dump_policy(json &ojson)
{
    if (policy(dump_policy)->verify() != vmcall_verifier::allow)
        policy(dump_policy)->deny_vmcall();

    for (const auto &pair : m_verifiers)
        ojson[get_typename(*pair.second)] = pair.second->to_string();

    bfdebug << "dump_policy: success" << bfendl;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__dump_denials(json &ojson)
{
    if (policy(dump_denials)->verify() != vmcall_verifier::allow)
        policy(dump_denials)->deny_vmcall();

    for (const auto &str : m_denials)
        ojson.push_back(str);

    bfdebug << "dump_denials: success" << bfendl;
}
