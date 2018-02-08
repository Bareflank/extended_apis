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

namespace ept_p = ::intel_x64::vmcs::ept_pointer;
namespace proc_ctls2 = ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls;
using vmcs = eapis::intel_x64::vmcs;

void
vmcs::enable_ept(vmcs::eptp_type eptp)
{
    ept_entry entry{&eptp};

    ept_p::phys_addr::set(entry.phys_addr());
    ept_p::memory_type::set(ept_p::memory_type::write_back);
    ept_p::page_walk_length_minus_one::set(3ULL);

    proc_ctls2::enable_ept::enable();
}

void
vmcs::disable_ept()
{
    ::intel_x64::vmx::invept_global();
    proc_ctls2::enable_ept::disable();

    ept_p::set(0UL);
}

void
vmcs::set_eptp(integer_pointer eptp)
{
    auto &&entry = ept_entry{&eptp};

    ept_p::memory_type::set(ept_p::memory_type::write_back);
    ept_p::page_walk_length_minus_one::set(3UL);
    ept_p::phys_addr::set(entry.phys_addr());
}
