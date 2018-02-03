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
#include "../../../../../include/hve/arch/intel_x64/exit_handler/vmcall_interface.h"

#include "../../../../../include/hve/arch/intel_x64/exit_handler/verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/vpid_verifiers.h"

using namespace x64;
namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;

void
exit_handler_intel_x64_eapis::register_json_vmcall__vpid()
{
    m_json_commands["enable_vpid"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__enable_vpid(ijson.at("enabled"));
        this->json_success(ojson);
    };
}

void
exit_handler_intel_x64_eapis::handle_vmcall__vpid(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
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

void
exit_handler_intel_x64_eapis::handle_vmcall__enable_vpid(bool enabled)
{
    if (policy(enable_vpid)->verify(enabled) != vmcall_verifier::allow) {
        policy(enable_vpid)->deny_vmcall();
    }

    if (enabled) {
        m_vmcs_eapis->enable_vpid();
        bfdebug_text(1, "enable_vpid", "success");
    }
    else {
        m_vmcs_eapis->disable_vpid();
        bfdebug_text(1, "disable_vpid", "success");
    }
}
