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

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

using cr0_value_type = intel_x64::cr0::value_type;
using cr3_value_type = intel_x64::cr3::value_type;
using cr4_value_type = intel_x64::cr4::value_type;

void
vmcs_intel_x64_eapis::enable_cr0_load_hook(cr0_value_type(*callback)(cr0_value_type), uint64_t cr0_guest_host_mask, uint64_t cr0_read_shadow)
{
    cr0_load_callback = callback;

    cr0_guest_host_mask::set(cr0_guest_host_mask);
    cr0_read_shadow::set(cr0_read_shadow);
}

void
vmcs_intel_x64_eapis::enable_cr3_load_hook(cr3_value_type(*callback)(cr3_value_type))
{
    cr3_load_callback = callback;
    primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr3_store_hook(cr3_value_type(*callback)(cr3_value_type))
{
    cr3_store_callback = callback;
    primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr4_load_hook(cr4_value_type(*callback)(cr4_value_type), uint64_t cr4_guest_host_mask, uint64_t cr4_read_shadow)
{
    cr4_load_callback = callback;

    cr4_guest_host_mask::set(cr4_guest_host_mask);
    cr4_read_shadow::set(cr4_read_shadow);
}

void
vmcs_intel_x64_eapis::enable_cr8_load_hook(cr8_value_type(*callback)(cr8_value_type))
{
    cr8_load_callback = callback;
    primary_processor_based_vm_execution_controls::cr8_load_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr8_store_hook(cr8_value_type(*callback)(cr8_value_type))
{
    cr8_store_callback = callback;
    primary_processor_based_vm_execution_controls::cr8_store_exiting::enable();
}

void vmcs_intel_x64_eapis::disable_cr0_load_hook()
{
    cr0_guest_host_mask::set(0UL);
    cr0_load_callback = nullptr;
}


void vmcs_intel_x64_eapis::disable_cr3_load_hook()
{
    primary_processor_based_vm_execution_controls::cr3_load_exiting::disable();
    cr3_load_callback = nullptr;
}

void vmcs_intel_x64_eapis::disable_cr3_store_hook()
{
    primary_processor_based_vm_execution_controls::cr3_store_exiting::disable();
    cr3_store_callback = nullptr;
}

void vmcs_intel_x64_eapis::disable_cr4_load_hook()
{
    cr4_guest_host_mask::set(0UL);
    cr4_load_callback = nullptr;
}

void vmcs_intel_x64_eapis::disable_cr8_load_hook()
{
    primary_processor_based_vm_execution_controls::cr8_load_exiting::disable();
    cr8_load_callback = nullptr;
}

void vmcs_intel_x64_eapis::disable_cr8_store_hook()
{
    primary_processor_based_vm_execution_controls::cr8_store_exiting::disable();
    cr8_store_callback = nullptr;
}
