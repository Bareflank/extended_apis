//
// Bareflank Hypervisor
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

#include <arch/intel_x64/apic/ioapic.h>
#include <hve/arch/intel_x64/virt_ioapic.h>

namespace eapis
{
namespace intel_x64
{

namespace ioapic = ::intel_x64::ioapic;

virt_ioapic::virt_ioapic() :
    m_select{0U}
{
    /// Init registers 0-2
    m_reg.at(ioapic::id::offset) = ioapic::id::default_val;
    m_reg.at(ioapic::ver::offset) = ioapic::ver::default_val;
    m_reg.at(ioapic::arb::offset) = ioapic::arb::default_val;

    /// Init registers 16-63 (RTEs)
    for (ioapic::offset_t i = ioapic::rte_begin; i < ioapic::rte_end; ++i) {
        m_reg.at(i) = gsl::narrow_cast<uint32_t>(ioapic::rte::mask_bit::enable(0U));
    }
}

virt_ioapic::virt_ioapic(gsl::not_null<eapis::intel_x64::phys_ioapic *> phys) :
    m_select{0U}
{
    ::x64::rflags::interrupt_enable_flag::disable();

    for (ioapic::offset_t i = 0x0U; i < ioapic::rte_end; ++i) {
        if (!ioapic::exists(i)) {
            m_reg.at(i) = 0U;
            continue;
        }

        phys->select(i);
        m_reg.at(i) = phys->read();
    }

    ::x64::rflags::interrupt_enable_flag::enable();
}

ioapic::value_t
virt_ioapic::read() const
{ return m_reg.at(m_select); }

void
virt_ioapic::write(ioapic::value_t val)
{
    expects(ioapic::is_writable(m_select));
    m_reg.at(m_select) = val;
}

void
virt_ioapic::select(ioapic::offset_t offset)
{
    expects(ioapic::exists(offset));
    m_select = offset;
}

}
}
