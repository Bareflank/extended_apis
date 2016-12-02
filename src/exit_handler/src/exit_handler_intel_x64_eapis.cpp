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

#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

exit_handler_intel_x64_eapis::exit_handler_intel_x64_eapis() :
    m_monitor_trap_callback(&exit_handler_intel_x64_eapis::unhandled_monitor_trap_callback),
    m_io_access_log_enabled(false),
    m_trapped_port(0),
    m_vmcs_eapis(nullptr)
{ }

void
exit_handler_intel_x64_eapis::resume()
{ eapis_vmcs()->resume(); }

void
exit_handler_intel_x64_eapis::advance_and_resume()
{
    this->advance_rip();
    eapis_vmcs()->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit(vmcs::value_type reason)
{
    switch (reason)
    {
        case exit_reason::basic_exit_reason::monitor_trap_flag:
            handle_exit__monitor_trap_flag();
            break;

        case exit_reason::basic_exit_reason::io_instruction:
            handle_exit__io_instruction();
            break;

        default:
            exit_handler_intel_x64::handle_exit(reason);
            break;
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_registers(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case eapis_cat__io_instruction:
            handle_vmcall_registers__io_instruction(regs);
            break;

        default:
            throw std::runtime_error("unknown vmcall category");
    }
}

void
exit_handler_intel_x64_eapis::handle_vmcall_data_string_json(
    vmcall_registers_t &regs, const json &str,
    const bfn::unique_map_ptr_x64<char> &omap)
{
    if (handle_vmcall_json__io_instruction(regs, str, omap))
        return;

    throw std::runtime_error("unknown JSON command");
}
