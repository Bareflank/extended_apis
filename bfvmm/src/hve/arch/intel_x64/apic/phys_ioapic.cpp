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
#include <hve/arch/intel_x64/apic/phys_ioapic.h>

namespace eapis
{
namespace intel_x64
{

namespace ioapic = ::intel_x64::ioapic;

phys_ioapic::phys_ioapic(ioapic::base_t base)
{
    expects(base != 0U);
    expects(base == ioapic::align_base(base));

    m_base = base;
}

ioapic::base_t
phys_ioapic::base() const
{ return m_base; }

void
phys_ioapic::relocate(ioapic::base_t base)
{
    expects(base != 0U);
    expects(base == ioapic::align_base(base));

    m_base = base;
}

ioapic::value_t
phys_ioapic::read()
{ return this->get_ioregwin(); }

void
phys_ioapic::write(ioapic::value_t val)
{
    const auto sel = gsl::narrow_cast<ioapic::offset_t>(this->get_ioregsel());
    expects(ioapic::is_writable(sel));
    this->set_ioregwin(val);
}

void
phys_ioapic::select(ioapic::offset_t offset)
{
    expects(ioapic::exists(offset));
    this->set_ioregsel(offset);
}

void
phys_ioapic::set_ioregsel(ioapic::offset_t offset)
{
    constexpr auto sel_offset = 0x00U;
    auto addr = reinterpret_cast<ioapic::value_t *>(m_base + sel_offset);
    *addr = offset;
}

ioapic::value_t
phys_ioapic::get_ioregsel() const
{
    constexpr auto sel_offset = 0x00U;
    auto addr = reinterpret_cast<ioapic::value_t *>(m_base + sel_offset);
    return *addr;
}

void
phys_ioapic::set_ioregwin(ioapic::value_t val)
{
    constexpr auto win_offset = 0x10U;
    auto addr = reinterpret_cast<ioapic::value_t *>(m_base + win_offset);
    *addr = val;
}

ioapic::value_t
phys_ioapic::get_ioregwin() const
{
    constexpr auto win_offset = 0x10U;
    auto addr = reinterpret_cast<ioapic::value_t *>(m_base + win_offset);
    return *addr;
}

}
}
