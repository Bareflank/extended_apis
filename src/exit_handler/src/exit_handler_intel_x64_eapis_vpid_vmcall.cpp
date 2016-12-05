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
using namespace vmcs;

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__vpid(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__enable_vpid:
            handle_vmcall__enable_vpid(true);
            break;

        case eapis_fun__disable_vpid:
            handle_vmcall__enable_vpid(false);
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

bool
exit_handler_intel_x64_eapis::handle_vmcall_json__vpid(
    vmcall_registers_t &regs, const json &str,
    const bfn::unique_map_ptr_x64<char> &omap)
{
    auto set = str.value("set", std::string());

    if (!set.empty())
    {
        if (set == "vpid")
        {
            handle_vmcall__enable_vpid(str.value("enabled", false));
            reply_with_string(regs, "success", omap);
            return true;
        }
    }

    return false;
}

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_vpid(bool enabled)
{
    if (policy(enable_vpid)->verify(enabled) != vmcall_verifier::allow)
        policy(enable_vpid)->deny_vmcall();

    if (enabled)
    {
        eapis_vmcs()->enable_vpid();
        bfdebug << "enable_vpid: success" << bfendl;
    }
    else
    {
        eapis_vmcs()->disable_vpid();
        bfdebug << "disable_vpid: success" << bfendl;
    }
}
