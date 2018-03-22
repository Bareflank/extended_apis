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

#ifndef VIC_INTEL_X64_EAPIS_H
#define VIC_INTEL_X64_EAPIS_H

#include "../../../hve/arch/intel_x64/hve.h"
#include "lapic_register.h"
#include "phys_x2apic.h"
#include "virt_x2apic.h"

namespace eapis
{
namespace intel_x64
{

///
/// Virtual interrupt controller (VIC)
///
class EXPORT_EAPIS_VIC vic
{
public:

    using handler_delegate_t = external_interrupt::handler_delegate_t;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vic(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vic();

    ///
    /// Physical vector to virtual vector
    ///
    /// Return the virtual interrupt vector the provided physical
    /// vector maps to
    ///
    /// @expects
    /// @ensures
    ///
    /// @param piv the physical interrupt vector
    ///
    uint64_t phys_to_virt(uint64_t piv);

    /// Virtual vector to physical vector
    ///
    /// Return the physical interrupt vector the provided virtual
    /// vector maps to
    ///
    /// @expects
    /// @ensures
    ///
    /// @param viv the physical interrupt vector
    ///
    uint64_t virt_to_phys(uint64_t viv);

    ///
    /// Map
    ///
    /// Associate the virtual interrupt vector with the given
    /// physical interrupt vector
    ///
    /// @expects
    /// @ensures
    ///
    /// @param viv the virtual interrupt vector
    /// @param piv the physical interrupt vector
    ///
    void map(uint64_t viv, uint64_t piv);

    ///
    /// Unmap
    ///
    /// Disassociate the virtual interrupt vector with
    /// its physical interrupt vector
    ///
    /// @expects
    /// @ensures
    ///
    /// @param viv the virtual interrupt vector to unmap
    ///
    void unmap(uint64_t viv);

    ///
    /// Send physical IPI
    ///
    /// Send an IPI to this pcpu
    ///
    /// @expects
    /// @ensures
    ///
    /// @param icr the value to write to the ICR
    ///
    void send_phys_ipi(uint64_t icr);

    ///
    /// Send virtual IPI
    ///
    /// Inject the provided IPI to this vcpu
    ///
    /// @expects
    /// @ensures
    ///
    /// @param icr the value to write to the ICR
    ///
    void send_virt_ipi(uint64_t icr);

    ///
    /// Add interrupt handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector the handler handles
    /// @param d the handler delegate
    ///
    void add_interrupt_handler(
        uint64_t vector, handler_delegate_t &&d
    );

    /// Handle interrupt
    ///
    /// @expects
    /// @ensures
    ///
    void handle_interrupt(uint64_t vector);

    /// Handle external interrupt exit
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_external_interrupt_exit(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info);

    /// Handle interrupt from exit
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_interrupt_from_exit(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info);

    /// Handle x2apic read exit
    ///
    /// Handle guest attempts to read an x2apic register
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_x2apic_read(
        gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info);

    /// Handle x2apic write exit
    ///
    /// Handle guest attempts to write an x2apic register
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_x2apic_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle x2apic EOI write
    ///
    /// Handle guest attempts to write an EOI
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_x2apic_eoi_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle x2apic ICR write exit
    ///
    /// Handle guest attempts to write to the ICR
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_x2apic_icr_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle x2apic self-IPI write exit
    ///
    /// Handle guest attempts to write to the self-IPI
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_x2apic_self_ipi_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle cr8 read exit
    ///
    /// Handle guest attempts to read cr8
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_rdcr8(
        gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);

    /// Handle cr8 write exit
    ///
    /// Handle guest attempts to write cr8
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_wrcr8(
        gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);

    /// Handle read to IA32_APIC_BASE MSR
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_rdmsr_apic_base(
        gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info);

    /// Handle write to IA32_APIC_BASE MSR
    ///
    /// @expects
    /// @ensures
    ///
    bool handle_wrmsr_apic_base(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

private:

    /// @cond

    void add_exit_handlers();
    void add_cr8_handlers();
    void add_apic_base_handlers();
    void add_external_interrupt_handlers();

    void add_x2apic_handlers();
    void add_x2apic_read_handler(lapic_register::offset_t offset);
    void add_x2apic_write_handler(lapic_register::offset_t offset);

    void init_phys_idt();
    void init_phys_lapic();
    void init_phys_x2apic();
    void init_virt_lapic();
    void init_save_state();
    void init_interrupt_map();

    bool handle_spurious_interrupt(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info);

    eapis::intel_x64::hve *m_hve;

    std::unique_ptr<gsl::byte[]> m_ist1;
    std::unique_ptr<eapis::intel_x64::virt_lapic> m_virt_lapic;
    std::unique_ptr<eapis::intel_x64::phys_lapic> m_phys_lapic;

    std::array<std::list<handler_delegate_t>, 256> m_handlers;
    std::array<uint64_t, 256> m_interrupt_map;
    uint64_t m_virt_apic_base;

    /// @endcond

public:

    /// @cond

    vic(vic &&) = default;
    vic &operator=(vic &&) = default;

    vic(const vic &) = delete;
    vic &operator=(const vic &) = delete;

    /// @endcond
};

}
}

#endif
