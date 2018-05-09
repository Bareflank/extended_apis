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

#ifndef PHYS_LAPIC_INTEL_X64_EAPIS_H
#define PHYS_LAPIC_INTEL_X64_EAPIS_H

#include "base.h"

namespace eapis
{
namespace intel_x64
{

/// Physical Local APIC
///
/// Provides an interface for reading and writing a physical local apic.
/// The interface is abstracted over both xAPIC and x2APIC.
///
class EXPORT_EAPIS_HVE phys_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    phys_lapic() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~phys_lapic() = default;

    /// Base
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the linear base address of the physical APIC
    /// @note this is only well-defined for xAPIC mode
    ///
    virtual uintptr_t base() = 0;

    /// Relocate
    ///
    /// @expects
    /// @ensures
    ///
    /// @param base the new base address of the apic
    ///
    virtual void relocate(uintptr_t base) = 0;

    /// Enable interrupts
    ///
    /// Enable physical interrupts on this cpu
    ///
    /// @expects
    /// @ensures
    ///
    virtual void enable_interrupts() = 0;

    /// Disable interrupts
    ///
    /// Disable physical interrupts on this cpu
    ///
    /// @expects
    /// @ensures
    ///
    virtual void disable_interrupts() = 0;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to read
    /// @return the value of the register at the provided offset
    ///
    virtual uint64_t read_register(uint64_t offset) const = 0;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the canonical offset to write
    /// @param val the value to write
    ///
    virtual void write_register(uint64_t offset, uint64_t val) = 0;

    /// Read ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the ID register
    ///
    virtual uint64_t read_id() const = 0;

    /// Read version
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the version register
    ///
    virtual uint64_t read_version() const = 0;

    /// Read TPR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the TPR
    ///
    virtual uint64_t read_tpr() const = 0;

    /// Read SVR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the SVR
    ///
    virtual uint64_t read_svr() const = 0;

    /// Read ICR
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the ICR
    ///
    virtual uint64_t read_icr() const = 0;

    /// Write EOI
    ///
    /// @expects
    /// @ensures
    ///
    virtual void write_eoi() = 0;

    /// Write TPR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param tpr the value of the tpr to write
    ///
    virtual void write_tpr(uint64_t tpr) = 0;

    /// Write SVR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param svr the value of the SVR to write
    ///
    virtual void write_svr(uint64_t svr) = 0;

    /// Write ICR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param icr the value of the ICR to write
    ///
    virtual void write_icr(uint64_t icr) = 0;

    /// Write self-IPI
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector of the self-IPI to send
    ///
    virtual void write_self_ipi(uint64_t vector) = 0;

    /// @cond

    phys_lapic(phys_lapic &&) = default;
    phys_lapic &operator=(phys_lapic &&) = default;

    phys_lapic(const phys_lapic &) = delete;
    phys_lapic &operator=(const phys_lapic &) = delete;

    /// @endcond
};

}
}

#endif
