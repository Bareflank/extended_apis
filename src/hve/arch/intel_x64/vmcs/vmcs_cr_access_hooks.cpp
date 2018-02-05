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

#include "../../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"
#include <intrinsics.h>

namespace vmcs = ::intel_x64::vmcs;
namespace proc_ctls = vmcs::primary_processor_based_vm_execution_controls;
namespace vmcs_eapis = eapis::hve::intel_x64::vmcs;

void
vmcs_eapis::vmcs::enable_cr0_load_hook(mask_type mask, shadow_type shadow)
{
    vmcs::cr0_guest_host_mask::set(mask);
    vmcs::cr0_read_shadow::set(shadow);
}

void
vmcs_eapis::vmcs::enable_cr3_load_hook()
{
    proc_ctls::cr3_load_exiting::enable();
}

void
vmcs_eapis::vmcs::enable_cr3_store_hook()
{
    proc_ctls::cr3_store_exiting::enable();
}

void
vmcs_eapis::vmcs::enable_cr4_load_hook(mask_type mask, shadow_type shadow)
{
    vmcs::cr4_guest_host_mask::set(mask);
    vmcs::cr4_read_shadow::set(shadow);
}

void
vmcs_eapis::vmcs::enable_cr8_load_hook()
{
    proc_ctls::cr8_load_exiting::enable();
}

void
vmcs_eapis::vmcs::enable_cr8_store_hook()
{
    proc_ctls::cr8_store_exiting::enable();
}

void vmcs_eapis::vmcs::disable_cr0_load_hook()
{
    vmcs::cr0_guest_host_mask::set(0ULL);
    vmcs::cr0_read_shadow::set(0ULL);
}

void vmcs_eapis::vmcs::disable_cr3_load_hook()
{
    proc_ctls::cr3_load_exiting::disable();
}

void vmcs_eapis::vmcs::disable_cr3_store_hook()
{
    proc_ctls::cr3_store_exiting::disable();
}

void vmcs_eapis::vmcs::disable_cr4_load_hook()
{
    vmcs::cr4_guest_host_mask::set(0ULL);
    vmcs::cr4_read_shadow::set(0ULL);
}

void vmcs_eapis::vmcs::disable_cr8_load_hook()
{
    proc_ctls::cr8_load_exiting::disable();
}

void vmcs_eapis::vmcs::disable_cr8_store_hook()
{
    proc_ctls::cr8_store_exiting::disable();
}
