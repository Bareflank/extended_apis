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

#include "../../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/vmcall_interface.h"

#include "../../../../../include/hve/arch/intel_x64/exit_handler/verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/msr_verifiers.h"

namespace exit_handler_eapis = eapis::hve::intel_x64::exit_handler;

void
exit_handler_eapis::exit_handler::register_json_vmcall__msr()
{
    m_json_commands["enable_msr_bitmap"] = [&](const auto & ijson, auto & ojson) {
        this->handle_vmcall__enable_msr_bitmap(ijson.at("enabled"));
        this->json_success(ojson);
    };
}

void
exit_handler_eapis::exit_handler::handle_vmcall__msr(
    vmcall_registers_t &regs)
{
    switch (regs.r03) {
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
exit_handler_eapis::exit_handler::handle_vmcall__enable_msr_bitmap(
    bool enabled)
{
    if (policy(enable_msr_bitmap)->verify(enabled) != vmcall_verifier::allow) {
        policy(enable_msr_bitmap)->deny_vmcall();
    }

    if (enabled) {
        m_vmcs_eapis->enable_msr_bitmap();
        bfdebug_text(1, "enable_msr_bitmap", "success");
    }
    else {
        m_vmcs_eapis->disable_msr_bitmap();
        bfdebug_text(1, "disable_msr_bitmap", "success");
    }
}
