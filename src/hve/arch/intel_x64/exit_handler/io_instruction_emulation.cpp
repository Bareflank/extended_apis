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
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>

namespace proc_ctls = ::intel_x64::vmcs::primary_processor_based_vm_execution_controls;
using ehlr_eapis = eapis::intel_x64::exit_handler;

void
ehlr_eapis::trap_on_io_access_callback()
{
    proc_ctls::use_io_bitmaps::enable();
    this->resume();
}

void
ehlr_eapis::handle_exit__io_instruction()
{
    register_monitor_trap(&ehlr_eapis::trap_on_io_access_callback);

    proc_ctls::use_io_bitmaps::disable();
    this->resume();
}
