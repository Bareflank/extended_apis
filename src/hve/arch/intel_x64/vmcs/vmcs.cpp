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

#include <bfdebug.h>
#include "../../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"

namespace eapis
{
namespace intel_x64
{

vmcs::vmcs(vcpuid::type vcpuid) :
    ::bfvmm::intel_x64::vmcs(vcpuid)
{
    static ::intel_x64::vmcs::value_type g_vpid = 1;
    m_vpid = g_vpid++;

    bfdebug_info(0, "constructed eapis::vmcs");
}

}
}
//void
//vmcs::write_fields(gsl::not_null<bfvmm::intel_x64::vmcs_state *> host_state,
//                   gsl::not_null<bfvmm::intel_x64::vmcs_state *> guest_state)
//{
//    bfignored(host_state);
//    bfignored(guest_state);
//
//    this->disable_ept();
//    this->disable_vpid();
//    this->disable_io_bitmaps();
//    this->disable_msr_bitmap();
//    this->disable_msr_bitmap();
//    this->disable_cr0_load_hook();
//    this->disable_cr3_load_hook();
//    this->disable_cr3_store_hook();
//    this->disable_cr4_load_hook();
//    this->disable_cr8_load_hook();
//    this->disable_cr8_store_hook();
//    this->disable_event_management();
//}
