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

ept_handler::ept_handler()
{ }

void ept_handler::set_eptp(ept::mmap *map)
{
    if (map) {
        vmcs_n::ept_pointer::phys_addr::set(map->eptp());

        if (!m_enabled) {
            vmcs_n::ept_pointer::memory_type::set(vmcs_n::ept_pointer::memory_type::write_back);
            vmcs_n::ept_pointer::accessed_and_dirty_flags::disable();
            vmcs_n::ept_pointer::page_walk_length_minus_one::set(3U);

            vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::enable();
            m_enabled = true;
        }
    }
    else {
        if (m_enabled) {
            vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::disable();
            m_enabled = false;
        }

        vmcs_n::ept_pointer::set(0);
    }
}

}
}
