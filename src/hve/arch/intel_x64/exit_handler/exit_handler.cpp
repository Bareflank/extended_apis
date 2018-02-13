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

#include <intrinsics.h>

namespace reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason;
using exit_handler = eapis::intel_x64::exit_handler;

exit_handler::exit_handler() :
    m_monitor_trap_callback(&exit_handler::unhandled_monitor_trap_callback),
    m_vmcs_eapis(nullptr)
{
}

void
exit_handler::resume()
{
    m_vmcs_eapis->resume();
}

void
exit_handler::advance_and_resume()
{
    this->advance_rip();
    m_vmcs_eapis->resume();
}

void
exit_handler::handle_exit(::intel_x64::vmcs::value_type reason)
{
    switch (reason) {
        case reason::monitor_trap_flag:
            handle_exit__monitor_trap_flag();
            break;

        case reason::io_instruction:
            handle_exit__io_instruction();
            break;

        case reason::rdmsr:
            handle_exit__rdmsr();
            break;

        case reason::wrmsr:
            handle_exit__wrmsr();
            break;

        case reason::control_register_accesses:
            handle_exit__ctl_reg_access();
            break;

        case reason::cpuid:
            handle_exit__cpuid();
            break;

        default:
            bfvmm::intel_x64::exit_handler::handle_exit(reason);
            break;
    }
}
