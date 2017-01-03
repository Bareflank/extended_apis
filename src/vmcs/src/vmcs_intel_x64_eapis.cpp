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

#include <memory_manager/memory_manager_x64.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

vmcs_intel_x64_eapis::vmcs_intel_x64_eapis() :
    m_io_bitmapa{std::make_unique<uint8_t[]>(x64::page_size)},
    m_io_bitmapb{std::make_unique<uint8_t[]>(x64::page_size)},
    m_io_bitmapa_view{m_io_bitmapa, x64::page_size},
    m_io_bitmapb_view{m_io_bitmapb, x64::page_size}
{
    static vmcs::value_type g_vpid = 1;
    m_vpid = g_vpid++;
}

void
vmcs_intel_x64_eapis::write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                                   gsl::not_null<vmcs_intel_x64_state *> guest_state)
{
    vmcs_intel_x64::write_fields(host_state, guest_state);

    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmapa.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmapb.get()));
    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();

    this->disable_ept();
    this->disable_vpid();
    this->pass_through_all_io_accesses();
}
