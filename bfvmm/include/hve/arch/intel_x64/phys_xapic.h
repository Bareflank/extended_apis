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

#ifndef PHYS_XAPIC_INTEL_X64_EAPIS_H
#define PHYS_XAPIC_INTEL_X64_EAPIS_H

#include "phys_lapic.h"

namespace eapis
{
namespace intel_x64
{

/// Physical xAPIC
///
/// This class implements the lapic interface for xapic
/// mode. It is marked final because it is intended to interact
/// directly with xapic hardware.
///
class EXPORT_EAPIS_HVE phys_xapic final : public phys_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    //
    /// @param base the address of the apic
    ///
    phys_xapic(uintptr_t base);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_xapic() override = default;

    /// Base
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the linear base address of the physical APIC
    /// @note this is only well-defined for xAPIC mode
    ///
    uintptr_t base() override;

    /// Relocate
    ///
    /// @expects
    /// @ensures
    ///
    /// @param base the new base address of the apic
    ///
    void relocate(uintptr_t base) override;

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

    /// Reset from INIT signal
    ///
    /// @expects
    /// @ensures
    ///
    void reset_from_init() override;

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

    phys_xapic(phys_xapic &&) = default;
    phys_xapic &operator=(phys_xapic &&) = default;

    phys_xapic(const phys_xapic &) = delete;
    phys_xapic &operator=(const phys_xapic &) = delete;

private:
    static const uint64_t s_page_size = 4096U;
    uintptr_t m_base;

    /// @endcond
};

}
}

#endif
