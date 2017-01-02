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

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>

#include <vmcs/ept_entry_intel_x64.h>

using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_ept()
{
    secondary_processor_based_vm_execution_controls::enable_ept::enable();
    intel_x64::vmx::invept_global();
}

void
vmcs_intel_x64_eapis::disable_ept()
{
    intel_x64::vmx::invept_global();
    secondary_processor_based_vm_execution_controls::enable_ept::disable();

    ept_pointer::set(0UL);
}

void
vmcs_intel_x64_eapis::set_eptp(integer_pointer eptp)
{
    auto &&entry = ept_entry_intel_x64{&eptp};

    ept_pointer::memory_type::set(ept_pointer::memory_type::write_back);
    ept_pointer::page_walk_length_minus_one::set(3UL);
    ept_pointer::phys_addr::set(entry.phys_addr());
}
