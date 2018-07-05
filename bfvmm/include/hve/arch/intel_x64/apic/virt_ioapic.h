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

#ifndef VIRT_IOAPIC_INTEL_X64_EAPIS_H
#define VIRT_IOAPIC_INTEL_X64_EAPIS_H

#include <array>
#include <arch/intel_x64/apic/ioapic.h>
#include "phys_ioapic.h"

namespace eapis
{
namespace intel_x64
{

class hve;
class phys_ioapic;

///
/// Virtual IOAPIC
///
class EXPORT_EAPIS_HVE virt_ioapic
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    virt_ioapic();

    /// Constructor from physical IOAPIC
    ///
    /// @expects
    /// @ensures
    ///
    /// @param phys the phys_ioapic object for this physical core
    ///
    virt_ioapic(gsl::not_null<eapis::intel_x64::phys_ioapic *> phys);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~virt_ioapic() = default;

    /// Read
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the 32-bit register given by the
    ///         previously select()'d register
    ///
    ::intel_x64::ioapic::value_t read() const;

    /// Write
    ///
    /// @expects
    /// @ensures
    ///
    /// @param val the 32-bit value to write to the previously
    ///        select()'d register
    ///
    void write(::intel_x64::ioapic::value_t val);

    /// Select
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to select for reading or writing
    ///
    void select(::intel_x64::ioapic::offset_t offset);

#ifndef ENABLE_BUILD_TEST
private:
#endif

    /// @cond

    ::intel_x64::ioapic::offset_t m_select;
    std::array<::intel_x64::ioapic::value_t, ::intel_x64::ioapic::rte_end> m_reg;

    /// @endcond

public:

    /// @cond

    virt_ioapic(virt_ioapic &&) = default;
    virt_ioapic &operator=(virt_ioapic &&) = default;

    virt_ioapic(const virt_ioapic &) = delete;
    virt_ioapic &operator=(const virt_ioapic &) = delete;

    /// @endcond
};


}
}

#endif
