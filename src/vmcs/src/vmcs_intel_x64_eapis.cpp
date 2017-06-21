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

vmcs_intel_x64_eapis::vmcs_intel_x64_eapis()
{
    static intel_x64::vmcs::value_type g_vpid = 1;
    m_vpid = g_vpid++;
}

void
vmcs_intel_x64_eapis::write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                                   gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    vmcs_intel_x64::write_fields(host_state, guest_state);

    this->disable_ept();
    this->disable_vpid();
    this->disable_io_bitmaps();
    this->disable_msr_bitmap();
}
