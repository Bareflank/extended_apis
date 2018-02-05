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

#include <intrinsics.h>

namespace exit_reason_basic = ::intel_x64::vmcs::exit_reason::basic_exit_reason;
namespace exit_handler_eapis = eapis::hve::intel_x64::exit_handler;

exit_handler_eapis::exit_handler::exit_handler() :
    m_monitor_trap_callback(&exit_handler_eapis::exit_handler::unhandled_monitor_trap_callback),
    m_io_access_log_enabled(false),
    m_vmcs_eapis(nullptr)
{
    init_policy();

    register_json_vmcall__verifiers();
    register_json_vmcall__io_instruction();
    register_json_vmcall__vpid();
    register_json_vmcall__msr();
    register_json_vmcall__rdmsr();
    register_json_vmcall__wrmsr();
}

void
exit_handler_eapis::exit_handler::resume()
{
    m_vmcs_eapis->resume();
}

void
exit_handler_eapis::exit_handler::advance_and_resume()
{
    this->advance_rip();
    m_vmcs_eapis->resume();
}

void
exit_handler_eapis::exit_handler::handle_exit(::intel_x64::vmcs::value_type reason)
{
    switch (reason)
    {
        case exit_reason_basic::monitor_trap_flag:
            handle_exit__monitor_trap_flag();
            break;

        case exit_reason_basic::io_instruction:
            handle_exit__io_instruction();
            break;

        case exit_reason_basic::rdmsr:
            handle_exit__rdmsr();
            break;

        case exit_reason_basic::wrmsr:
            handle_exit__wrmsr();
            break;

        case exit_reason_basic::control_register_accesses:
            handle_exit__ctl_reg_access();
            break;

        default:
            bfvmm::intel_x64::exit_handler::handle_exit(reason);
            break;
    }
}

void
exit_handler_eapis::exit_handler::handle_vmcall_registers(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case eapis_cat__io_instruction:
            handle_vmcall__io_instruction(regs);
            break;

        case eapis_cat__vpid:
            handle_vmcall__vpid(regs);
            break;

        case eapis_cat__msr:
            handle_vmcall__msr(regs);
            break;

        case eapis_cat__rdmsr:
            handle_vmcall__rdmsr(regs);
            break;

        case eapis_cat__wrmsr:
            handle_vmcall__wrmsr(regs);
            break;

        default:
            throw std::runtime_error("unknown vmcall category");
    }
}

void
exit_handler_eapis::exit_handler::handle_vmcall_data_string_json(
    const json &ijson, json &ojson)
{
    m_json_commands.at(ijson.at("command"))(ijson, ojson);
}

void
exit_handler_eapis::exit_handler::json_success(json &ojson)
{ ojson = {"success"}; }
