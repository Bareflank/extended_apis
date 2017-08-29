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

#include <intrinsics/x86/intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;
using namespace exit_qualification::control_register_access;

exit_handler_intel_x64_eapis::exit_handler_intel_x64_eapis()
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
exit_handler_intel_x64_eapis::resume()
{
    disable_vmm_exceptions();
    exit_handler_intel_x64::resume();
}

void
exit_handler_intel_x64_eapis::promote()
{
    disable_vmm_exceptions();
    exit_handler_intel_x64::promote();
}

void
exit_handler_intel_x64_eapis::handle_exit(vmcs::value_type reason)
{
    enable_vmm_exceptions();

    switch (reason) {
        case exit_reason::basic_exit_reason::monitor_trap_flag:
            handle_exit__monitor_trap_flag();
            break;

        case exit_reason::basic_exit_reason::io_instruction:
            handle_exit__io_instruction();
            break;

        case exit_reason::basic_exit_reason::rdmsr:
            handle_exit__rdmsr();
            break;

        case exit_reason::basic_exit_reason::wrmsr:
            handle_exit__wrmsr();
            break;

        case exit_reason::basic_exit_reason::control_register_accesses:
            handle_exit__ctl_reg_access();
            break;

        case exit_reason::basic_exit_reason::external_interrupt:
            handle_exit__external_interrupt();
            break;

        case exit_reason::basic_exit_reason::interrupt_window:
            handle_exit__interrupt_window();
            break;

        default:
            exit_handler_intel_x64::handle_exit(reason);
            break;
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers(vmcall_registers_t &regs)
{
    switch (regs.r02) {
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
exit_handler_intel_x64_eapis::handle_vmcall_data_string_json(
    const json &ijson, json &ojson)
{ m_json_commands.at(ijson.at("command"))(ijson, ojson); }

void
exit_handler_intel_x64_eapis::json_success(json &ojson)
{ ojson = {"success"}; }

exit_handler_intel_x64_eapis::gpr_value_type
exit_handler_intel_x64_eapis::get_gpr(gpr_index_type index)
{
    switch (index) {
        case general_purpose_register::rax:
            return m_state_save->rax;

        case general_purpose_register::rbx:
            return m_state_save->rbx;

        case general_purpose_register::rcx:
            return m_state_save->rcx;

        case general_purpose_register::rdx:
            return m_state_save->rdx;

        case general_purpose_register::rsp:
            return m_state_save->rsp;

        case general_purpose_register::rbp:
            return m_state_save->rbp;

        case general_purpose_register::rsi:
            return m_state_save->rsi;

        case general_purpose_register::rdi:
            return m_state_save->rdi;

        case general_purpose_register::r8:
            return m_state_save->r08;

        case general_purpose_register::r9:
            return m_state_save->r09;

        case general_purpose_register::r10:
            return m_state_save->r10;

        case general_purpose_register::r11:
            return m_state_save->r11;

        case general_purpose_register::r12:
            return m_state_save->r12;

        case general_purpose_register::r13:
            return m_state_save->r13;

        case general_purpose_register::r14:
            return m_state_save->r14;

        case general_purpose_register::r15:
            return m_state_save->r15;
    }

    throw std::runtime_error("unknown index");
}

void
exit_handler_intel_x64_eapis::set_gpr(
    gpr_index_type index, gpr_value_type val)
{
    switch (index) {
        case general_purpose_register::rax:
            m_state_save->rax = val;
            return;

        case general_purpose_register::rbx:
            m_state_save->rbx = val;
            return;

        case general_purpose_register::rcx:
            m_state_save->rcx = val;
            return;

        case general_purpose_register::rdx:
            m_state_save->rdx = val;
            return;

        case general_purpose_register::rsp:
            m_state_save->rsp = val;
            return;

        case general_purpose_register::rbp:
            m_state_save->rbp = val;
            return;

        case general_purpose_register::rsi:
            m_state_save->rsi = val;
            return;

        case general_purpose_register::rdi:
            m_state_save->rdi = val;
            return;

        case general_purpose_register::r8:
            m_state_save->r08 = val;
            return;

        case general_purpose_register::r9:
            m_state_save->r09 = val;
            return;

        case general_purpose_register::r10:
            m_state_save->r10 = val;
            return;

        case general_purpose_register::r11:
            m_state_save->r11 = val;
            return;

        case general_purpose_register::r12:
            m_state_save->r12 = val;
            return;

        case general_purpose_register::r13:
            m_state_save->r13 = val;
            return;

        case general_purpose_register::r14:
            m_state_save->r14 = val;
            return;

        case general_purpose_register::r15:
            m_state_save->r15 = val;
            return;
    }

    throw std::runtime_error("unknown index");
}
