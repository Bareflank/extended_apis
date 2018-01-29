//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Jonathan Cohen Scaly <scalys7@gmail.com>
// Author: Rian Quinn           <quinnr@ainfosec.com>
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

#include <hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfintrinsics/include/arch/intel_x64/vmcs/16bit_control_fields.h>
#include <bfintrinsics/include/arch/intel_x64/vmcs/32bit_control_fields.h>
#include <bfintrinsics/include/arch/intel_x64/vmcs/natural_width_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_cr0_load_hook(mask_type mask, shadow_type shadow)
{
    cr0_guest_host_mask::set(mask);
    cr0_read_shadow::set(shadow);
}

void
vmcs_intel_x64_eapis::enable_cr3_load_hook()
{
    primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr3_store_hook()
{
    primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr4_load_hook(mask_type mask, shadow_type shadow)
{
    cr4_guest_host_mask::set(mask);
    cr4_read_shadow::set(shadow);
}

void
vmcs_intel_x64_eapis::enable_cr8_load_hook()
{
    primary_processor_based_vm_execution_controls::cr8_load_exiting::enable();
}

void
vmcs_intel_x64_eapis::enable_cr8_store_hook()
{
    primary_processor_based_vm_execution_controls::cr8_store_exiting::enable();
}

void vmcs_intel_x64_eapis::disable_cr0_load_hook()
{
    cr0_guest_host_mask::set(0ULL);
    cr0_read_shadow::set(0ULL);
}

void vmcs_intel_x64_eapis::disable_cr3_load_hook()
{
    primary_processor_based_vm_execution_controls::cr3_load_exiting::disable();
}

void vmcs_intel_x64_eapis::disable_cr3_store_hook()
{
    primary_processor_based_vm_execution_controls::cr3_store_exiting::disable();
}

void vmcs_intel_x64_eapis::disable_cr4_load_hook()
{
    cr4_guest_host_mask::set(0ULL);
    cr4_read_shadow::set(0ULL);
}

void vmcs_intel_x64_eapis::disable_cr8_load_hook()
{
    primary_processor_based_vm_execution_controls::cr8_load_exiting::disable();
}

void vmcs_intel_x64_eapis::disable_cr8_store_hook()
{
    primary_processor_based_vm_execution_controls::cr8_store_exiting::disable();
}
