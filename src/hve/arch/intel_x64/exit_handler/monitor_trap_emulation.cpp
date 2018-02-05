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

#include <arch/intel_x64/vmcs/32bit_control_fields.h>
#include <arch/intel_x64/vmcs/32bit_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>

namespace proc_ctls = ::intel_x64::vmcs::primary_processor_based_vm_execution_controls;
namespace exit_handler_eapis = eapis::hve::intel_x64::exit_handler;

void
exit_handler_eapis::exit_handler::clear_monitor_trap()
{
    proc_ctls::monitor_trap_flag::disable();
    m_monitor_trap_callback = &exit_handler_eapis::exit_handler::unhandled_monitor_trap_callback;
}

void
exit_handler_eapis::exit_handler::unhandled_monitor_trap_callback()
{ throw std::logic_error("unhandled_monitor_trap_callback called!!!"); }

void
exit_handler_eapis::exit_handler::handle_exit__monitor_trap_flag()
{
    auto callback = m_monitor_trap_callback;

    clear_monitor_trap();
    (this->*callback)();
}
