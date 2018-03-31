//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef PHYS_X2APIC_INTEL_X64_EAPIS_H
#define PHYS_X2APIC_INTEL_X64_EAPIS_H

#include "phys_lapic.h"

namespace eapis
{
namespace intel_x64
{

/// Physical x2APIC
///
/// This class implements the lapic interface for x2apic
/// mode. It is marked final because it is intended to interact
/// directly with x2apic hardware.
///
class EXPORT_EAPIS_HVE phys_x2apic final : public phys_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    phys_x2apic() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_x2apic() override = default;

    /// Enable interrupts
    ///
    /// Enable physical interrupts on this cpu
    ///
    /// @expects
    /// @ensures
    ///
    void enable_interrupts() override;

    /// Disable interrupts
    ///
    /// Disable physical interrupts on this cpu
    ///
    /// @expects
    /// @ensures
    ///
    void disable_interrupts() override;

    /// Read Register
    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to read
    /// @return the value of the register at offset
    ///
    uint64_t read_register(uint64_t offset) const override;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to write
    /// @param val the value to write
    ///
    void write_register(uint64_t offset, uint64_t val) override;

    /// @cond

    ///
    /// Register reads
    ///
    uint64_t read_id() const override;
    uint64_t read_version() const override;
    uint64_t read_tpr() const override;
    uint64_t read_svr() const override;
    uint64_t read_icr() const override;

    ///
    /// Register writes
    ///
    void write_eoi() override;
    void write_tpr(uint64_t tpr) override;
    void write_svr(uint64_t svr) override;
    void write_icr(uint64_t icr) override;
    void write_self_ipi(uint64_t vector) override;

    phys_x2apic(phys_x2apic &&) = default;
    phys_x2apic &operator=(phys_x2apic &&) = default;

    phys_x2apic(const phys_x2apic &) = delete;
    phys_x2apic &operator=(const phys_x2apic &) = delete;

    /// @endcond
};

}
}

#endif
