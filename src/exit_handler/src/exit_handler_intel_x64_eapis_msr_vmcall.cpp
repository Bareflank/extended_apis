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
#include <exit_handler/exit_handler_intel_x64_eapis_msr_verifiers.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::register_json_vmcall__msr()
{
    m_json_commands["enable_msr_bitmap"] = [&](const auto & ijson, auto & ojson)
    {
        this->handle_vmcall__enable_msr_bitmap(ijson.at("enabled"));
        this->json_success(ojson);
    };
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers__msr(
    vmcall_registers_t &regs)
{
    switch (regs.r03)
    {
        case eapis_fun__enable_msr_bitmap:
            handle_vmcall__enable_msr_bitmap(true);
            break;

        case eapis_fun__disable_msr_bitmap:
            handle_vmcall__enable_msr_bitmap(false);
            break;

        default:
            throw std::runtime_error("unknown vmcall function");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_msr_bitmap(
    bool enabled)
{
    if (policy(enable_msr_bitmap)->verify(enabled) != vmcall_verifier::allow)
        policy(enable_msr_bitmap)->deny_vmcall();

    if (enabled)
    {
        m_vmcs_eapis->enable_msr_bitmap();
        vmcall_debug << "enable_msr_bitmap: success" << bfendl;
    }
    else
    {
        m_vmcs_eapis->disable_msr_bitmap();
        vmcall_debug << "disable_msr_bitmap: success" << bfendl;
    }
}
