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

#ifndef VIRT_X2APIC_INTEL_X64_EAPIS_H
#define VIRT_X2APIC_INTEL_X64_EAPIS_H

#include <array>

#include "lapic.h"

namespace eapis
{
namespace intel_x64
{

///
/// Virtual x2APIC
///
class EXPORT_EAPIS_VIC virt_x2apic : public lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    virt_x2apic(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~virt_x2apic() = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to read
    ///
    uint64_t read_register(uint64_t offset) const override;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to write
    /// @param val the value to write
    ///
    void write_register(uint64_t offset, uint64_t val) override;

    ///
    /// Register reads
    ///
    uint64_t read_id() const;
    uint64_t read_version() const;
    uint64_t read_tpr() const;
    uint64_t read_icr() const;

    ///
    /// Register writes
    ///
    void write_eoi();
    void write_tpr(uint64_t tpr);
    void write_icr(uint64_t icr);

private:

    /// @cond

    void reset_id();
    void reset_svr();
    void reset_version();
    void reset_registers();
    void reset_register(uint64_t offset);
    void reset_lvt_register(uint64_t offset);

    void clear_register(uint64_t offset);
    void insert(uint64_t offset, uint64_t value);

    eapis::intel_x64::vcpu *m_vcpu;
    std::array<uint64_t, lapic_register::count> m_registers;

    /// @endcond

public:

    /// @cond

    virt_x2apic(virt_x2apic &&) = default;
    virt_x2apic &operator=(virt_x2apic &&) = default;

    virt_x2apic(const virt_x2apic &) = delete;
    virt_x2apic &operator=(const virt_x2apic &) = delete;

    /// @endcond
};

}
}

#endif
