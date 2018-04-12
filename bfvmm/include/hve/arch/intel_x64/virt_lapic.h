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

#ifndef VIRT_LAPIC_INTEL_X64_EAPIS_H
#define VIRT_LAPIC_INTEL_X64_EAPIS_H

#include <array>
#include "lapic_register.h"

namespace eapis
{
namespace intel_x64
{

class hve;
class phys_xapic;
class phys_x2apic;

///
/// Virtual Local APIC
///
class EXPORT_EAPIS_HVE virt_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object of the virt_lapic
    ///
    virt_lapic(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Constructor from physical local APIC
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object of the virt_lapic
    /// @param phys the phys_lapic object of the physical core
    ///
    virt_lapic(
        gsl::not_null<eapis::intel_x64::hve *> hve,
        eapis::intel_x64::phys_lapic * phys);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~virt_lapic() = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to read
    /// @return the value of the 32-bit register given by offset
    ///
    uint64_t read_register(lapic_register::offset_t offset) const;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to write
    /// @param val the value to write
    ///
    void write_register(lapic_register::offset_t offset, uint64_t val);

    /// Handle interrupt window exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this exit
    /// @return true iff the exit is handled
    ///
    bool handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs);

    /// Queue Interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector of the interrupt to queue
    ///
    void queue_injection(uint64_t vector);

    /// Inject spurious interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the spurious vector inject
    ///
    void inject_spurious(uint64_t vector);

    /// @cond

    ///
    /// Register reads
    ///
    uint64_t read_id() const;
    uint64_t read_version() const;
    uint64_t read_tpr() const;
    uint64_t read_icr() const;
    uint64_t read_svr() const;

    ///
    /// Register writes
    ///
    void write_eoi();
    void write_tpr(uint64_t tpr);
    void write_icr(uint64_t icr);
    void write_self_ipi(uint64_t vector);
    void write_svr(uint64_t svr);

    /// @endcond

#ifndef ENABLE_BUILD_TEST
private:
#endif

    /// @cond

    void queue_interrupt(uint64_t vector);
    void inject_interrupt(uint64_t vector);

    void init_registers_from_phys_xapic(
        eapis::intel_x64::phys_xapic *phys);

    void init_registers_from_phys_x2apic(
        eapis::intel_x64::phys_x2apic *phys);

    void init_interrupt_window_handler();
    void init_id();

    void reset_svr();
    void reset_version();
    void reset_registers();
    void reset_register(lapic_register::offset_t offset);
    void reset_lvt_register(lapic_register::offset_t offset);
    void clear_register(lapic_register::offset_t offset);

    bool irr_is_empty();
    bool isr_is_empty();
    bool is_empty_256bit(uint64_t last);

    void pop_irr();
    void pop_isr();
    void pop_256bit(uint64_t last);

    uint64_t top_irr();
    uint64_t top_isr();
    uint64_t top_256bit(uint64_t last);

    eapis::intel_x64::hve *m_hve;
    std::array<uint32_t, lapic_register::count> m_registers;

    /// @endcond

public:

    /// @cond

    virt_lapic(virt_lapic &&) = default;
    virt_lapic &operator=(virt_lapic &&) = default;

    virt_lapic(const virt_lapic &) = delete;
    virt_lapic &operator=(const virt_lapic &) = delete;

    /// @endcond
};

}
}

#endif
