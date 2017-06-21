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

using namespace intel_x64;
using namespace vmcs;

void
exit_handler_intel_x64_eapis::log_io_access(bool enable)
{ m_io_access_log_enabled = enable; }

void
exit_handler_intel_x64_eapis::clear_io_access_log()
{ m_io_access_log.clear(); }

void
exit_handler_intel_x64_eapis::trap_on_io_access_callback()
{
    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__io_instruction()
{
    register_monitor_trap(&exit_handler_intel_x64_eapis::trap_on_io_access_callback);

    if (m_io_access_log_enabled) {
        m_io_access_log[exit_qualification::io_instruction::port_number::get()]++;
    }

    primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();
    this->resume();
}
