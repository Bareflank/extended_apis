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
#include <hve/arch/intel_x64/vpid.h>

namespace eapis
{
namespace intel_x64
{

vpid::vpid()
{
    static uint16_t s_id = 1;
    m_id = s_id++;

    vmcs_n::virtual_processor_identifier::set(m_id);
}

vmcs_n::value_type vpid::id() const noexcept
{ return m_id; }

void vpid::enable()
{ vmcs_n::secondary_processor_based_vm_execution_controls::enable_vpid::enable(); }

}
}
