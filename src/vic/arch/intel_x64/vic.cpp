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

#include <bfvmm/memory_manager/memory_manager.h>

#include <vic/arch/intel_x64/vic.h>

namespace eapis
{
namespace intel_x64
{

vic::vic(gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_hve{hve}
{
    m_interrupt_manager =
        std::make_unique<eapis::intel_x64::interrupt_manager>(m_hve);
}

gsl::not_null<eapis::intel_x64::hve *>
vic::hve()
{ return m_hve; }

gsl::not_null<eapis::intel_x64::interrupt_manager *>
vic::interrupt_manager()
{ return m_interrupt_manager.get(); }

void
vic::add_interrupt_handler(
    uint64_t vector, interrupt_manager::handler_delegate_t &&d)
{ m_interrupt_manager->add_interrupt_handler(vector, std::move(d)); }

}
}
