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
#include <intrinsics.h>
#include <intrinsics.h>

namespace proc_ctls2 = ::intel_x64::vmcs::secondary_processor_based_vm_execution_controls;
namespace vmcs_eapis = eapis::hve::intel_x64::vmcs;

void
vmcs_eapis::vmcs::enable_vpid()
{
    ::intel_x64::vmcs::virtual_processor_identifier::set(m_vpid);
    proc_ctls2::enable_vpid::enable();
}

void
vmcs_eapis::vmcs::disable_vpid()
{
    ::intel_x64::vmcs::virtual_processor_identifier::set(0UL);
    proc_ctls2::enable_vpid::disable();
}
