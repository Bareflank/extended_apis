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

    ///
    /// Register reads
    ///
    virtual uint64_t read_id() const = 0;
    virtual uint64_t read_version() const = 0;
    virtual uint64_t read_tpr() const = 0;
    virtual uint64_t read_svr() const = 0;
    virtual uint64_t read_icr() const = 0;

    ///
    /// Register writes
    ///
    virtual void write_eoi() = 0;
    virtual void write_tpr(uint64_t tpr) = 0;
    virtual void write_svr(uint64_t svr) = 0;
    virtual void write_icr(uint64_t icr) = 0;
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
