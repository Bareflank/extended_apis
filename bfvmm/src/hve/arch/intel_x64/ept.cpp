//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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
#include <hve/arch/intel_x64/vcpu.h>

namespace eapis
{
namespace intel_x64
{

ept_handler::ept_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state
) :
    m_eapis_vcpu_global_state{eapis_vcpu_global_state}
{
    bfignored(apis);
}

void ept_handler::set_eptp(ept::mmap *map)
{
    using namespace vmcs_n;
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

    if (map) {
        if (ept_pointer::phys_addr::get() == 0) {
            m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0 &= ~::intel_x64::cr0::paging::mask;
            m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0 &= ~::intel_x64::cr0::protection_enable::mask;

            ept_pointer::memory_type::set(ept_pointer::memory_type::write_back);
            ept_pointer::accessed_and_dirty_flags::disable();
            ept_pointer::page_walk_length_minus_one::set(3U);

            enable_ept::enable();
            unrestricted_guest::enable();
        }

        ept_pointer::phys_addr::set(map->eptp());
    }
    else {
        if (ept_pointer::phys_addr::get() != 0) {
            m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0 |= ::intel_x64::cr0::paging::mask;
            m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0 |= ::intel_x64::cr0::protection_enable::mask;

            ept_pointer::memory_type::set(0);
            ept_pointer::accessed_and_dirty_flags::disable();
            ept_pointer::page_walk_length_minus_one::set(0);

            enable_ept::disable();
            unrestricted_guest::disable();
        }

        ept_pointer::phys_addr::set(0);
    }
}

}
}
