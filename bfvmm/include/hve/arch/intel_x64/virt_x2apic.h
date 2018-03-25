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
#include <list>

#include "phys_x2apic.h"
#include "virt_lapic.h"
#include "lapic_register.h"

namespace eapis
{
namespace intel_x64
{

///
/// Virtual x2APIC
///
class EXPORT_EAPIS_HVE virt_x2apic final : public virt_lapic
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    virt_x2apic(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    virt_x2apic(
        gsl::not_null<eapis::intel_x64::hve *> hve,
        gsl::not_null<eapis::intel_x64::phys_lapic *> phys);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~virt_x2apic() override = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to read
    ///
    uint64_t read_register(lapic_register::offset_t offset) const override;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the register offset to write
    /// @param val the value to write
    ///
    void write_register(lapic_register::offset_t offset, uint64_t val) override;

    /// Handle interrupt window exit
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs) override;

    /// Queue Interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector of the interrupt to queue
    ///
    void queue_injection(uint64_t vector) override;

    ///
    /// Register reads
    ///
    uint64_t read_id() const override;
    uint64_t read_version() const override;
    uint64_t read_tpr() const override;
    uint64_t read_icr() const override;
    uint64_t read_svr() const override;

    ///
    /// Register writes
    ///
    void write_eoi() override;
    void write_tpr(uint64_t tpr) override;
    void write_icr(uint64_t icr) override;
    void write_self_ipi(uint64_t vector) override;
    void write_svr(uint64_t svr) override;

private:

    /// @cond

    void queue_interrupt(uint64_t vector);
    void inject_interrupt(uint64_t vector);

    void init_virt_from_phys_x2apic(
        eapis::intel_x64::phys_lapic *phys,
        lapic_register::offset_t offset);

    void init_registers_from_phys_x2apic(eapis::intel_x64::phys_lapic *phys);
    void init_interrupt_window_handler();

    void reset_id();
    void reset_svr();
    void reset_version();
    void reset_registers();
    void reset_register(lapic_register::offset_t offset);
    void reset_lvt_register(lapic_register::offset_t offset);
    void clear_register(lapic_register::offset_t offset);

    bool irr_is_empty();

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

    virt_x2apic(virt_x2apic &&) = default;
    virt_x2apic &operator=(virt_x2apic &&) = default;

    virt_x2apic(const virt_x2apic &) = delete;
    virt_x2apic &operator=(const virt_x2apic &) = delete;

    /// @endcond
};

}
}

#endif
