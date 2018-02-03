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

#include "../../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../../../include/hve/arch/intel_x64/vmcs/ept_entry.h"

#include <intrinsics.h>

namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;
namespace ept_ptr = vmcs::ept_pointer;
namespace proc_ctls2 = vmcs::secondary_processor_based_vm_execution_controls;

void
vmcs_intel_x64_eapis::enable_ept(eptp_type eptp)
{
    ept_entry_intel_x64 entry{&eptp};
    ept_ptr::phys_addr::set(entry.phys_addr());
    ept_ptr::memory_type::set(ept_ptr::memory_type::write_back);
    ept_ptr::page_walk_length_minus_one::set(3ULL);
    proc_ctls2::enable_ept::enable();
}

void
vmcs_intel_x64_eapis::disable_ept()
{
    intel::vmx::invept_global();
    proc_ctls2::enable_ept::disable();
    ept_ptr::set(0UL);
}

void
vmcs_intel_x64_eapis::set_eptp(integer_pointer eptp)
{
    auto &&entry = ept_entry_intel_x64{&eptp};

    ept_ptr::memory_type::set(ept_ptr::memory_type::write_back);
    ept_ptr::page_walk_length_minus_one::set(3UL);
    ept_ptr::phys_addr::set(entry.phys_addr());
}
