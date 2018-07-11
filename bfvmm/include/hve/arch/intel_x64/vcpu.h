//
// Bareflank Extended APIs
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

#ifndef VCPU_INTEL_X64_EAPIS_H
#define VCPU_INTEL_X64_EAPIS_H

#include "vmexit/control_register.h"
#include "vmexit/cpuid.h"
#include "vmexit/ept_misconfiguration.h"
#include "vmexit/ept_violation.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/init_signal.h"
#include "vmexit/interrupt_window.h"
#include "vmexit/io_instruction.h"
#include "vmexit/monitor_trap.h"
#include "vmexit/mov_dr.h"
#include "vmexit/rdmsr.h"
#include "vmexit/sipi.h"
#include "vmexit/wrmsr.h"

#include "misc/ept.h"
#include "misc/vpid.h"

#include <bfvmm/hve/arch/intel_x64/vcpu/vcpu.h>

namespace eapis
{
namespace intel_x64
{

/// vCPU
///
/// Manages the lifetime of the exit handlers created upon construction.
/// This class serves as the root from which all other resources may be
/// accessed, e.g. the vmcs and exit_handler.
///
class vcpu : public bfvmm::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    vcpu(vcpuid::type id);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

public:

    //==========================================================================
    // MISC
    //==========================================================================

    //--------------------------------------------------------------------------
    // EPT
    //--------------------------------------------------------------------------

    /// Get EPT Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT handler stored in the vcpu if EPT is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::ept_handler *> ept();

    /// Set EPTP
    ///
    /// Enables EPT and sets the EPTP to point to the provided mmap.
    /// If the provided mmap is a nullptr, EPT is disabled
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The map to set EPTP to.
    ///
    void set_eptp(ept::mmap *map);

    /// Set EPTP
    ///
    /// Enables EPT and sets the EPTP to point to the provided mmap.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The map to set EPTP to.
    ///
    void set_eptp(ept::mmap &map);

    /// Disable EPT
    ///
    /// @expects
    /// @ensures
    ///
    void disable_ept();

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Get VPID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID handler stored in the vcpu if VPID is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::vpid_handler *> vpid();

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    void enable_vpid();

    /// Disable VPID
    ///
    /// @expects
    /// @ensures
    ///
    void disable_vpid();

    //==========================================================================
    // VMExit
    //==========================================================================

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Get Control Register Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CR handler stored in the vcpu if CR trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::control_register_handler *> control_register();

    /// Enable Write CR0 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the cr0 guest/host mask to set in the vmcs
    /// @param shadow the cr0 read shadow to set in the vmcs
    ///
    void enable_wrcr0_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Write CR4 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the cr4 guest/host mask to set in the vmcs
    /// @param shadow the cr4 read shadow to set in the vmcs
    ///
    void enable_wrcr4_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr0 exit occurs
    ///
    void add_wrcr0_handler(control_register_handler::handler_delegate_t &&d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr3 exit occurs
    ///
    void add_rdcr3_handler(control_register_handler::handler_delegate_t &&d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr3 exit occurs
    ///
    void add_wrcr3_handler(control_register_handler::handler_delegate_t &&d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    void add_wrcr4_handler(control_register_handler::handler_delegate_t &&d);

    /// Add Read CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr8 exit occurs
    ///
    void add_rdcr8_handler(control_register_handler::handler_delegate_t &&d);

    /// Add Write CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr8 exit occurs
    ///
    void add_wrcr8_handler(control_register_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID handler stored in the vcpu if CPUID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::cpuid_handler *> cpuid();

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID at the given
    ///        leaf and subleaf
    ///
    void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, cpuid_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

    /// Get EPT misconfiguration object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT misconfiguration handler stored in the vcpu if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::ept_misconfiguration_handler *> ept_misconfiguration();

    /// Add EPT Misconfiguration Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_misconfiguration_handler(
        ept_misconfiguration_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // EPT Violation
    //--------------------------------------------------------------------------

    /// Get EPT violation object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT violation handler stored in the vcpu if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::ept_violation_handler *> ept_violation();

    /// Add EPT read violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_read_violation_handler(
        ept_violation_handler::handler_delegate_t &&d);

    /// Add EPT write violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_write_violation_handler(
        ept_violation_handler::handler_delegate_t &&d);

    /// Add EPT execute violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_execute_violation_handler(
        ept_violation_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

    /// Get External Interrupt Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the external interrupt handler stored in the vcpu if
    ///     external-interrupt exiting is enabled, otherwise an exception is
    ///     thrown
    ///
    gsl::not_null<eapis::intel_x64::external_interrupt_handler *> external_interrupt();

    /// Add External Interrupt Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to listen to
    /// @param d the delegate to call when an exit occurs with vector v
    ///
    void add_external_interrupt_handler(
        vmcs_n::value_type vector, external_interrupt_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // INIT Signal
    //--------------------------------------------------------------------------

    /// Get INIT Signal Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the INIT signal handler stored in the hve
    ///
    gsl::not_null<eapis::intel_x64::init_signal_handler *> init_signal();

    /// Add INIT Signal Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an INIT signal exit occurs
    ///
    void add_init_signal_handler(init_signal_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Get Interrupt Window Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the interrupt-window handler stored in the vcpu if
    ///
    gsl::not_null<eapis::intel_x64::interrupt_window_handler *> interrupt_window();

    /// Add Interrupt Window Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an interrupt-window exit occurs
    ///
    void add_interrupt_window_handler(interrupt_window_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Get IO Instruction Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the IO Instruction handler stored in the vcpu if IO
    ///     Instruction trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::io_instruction_handler *> io_instruction();

    /// Add IO Instruction Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to call
    /// @param in_d the delegate to call when the reads in from the given port
    /// @param out_d the delegate to call when the guest writes out to the
    ///        given port.
    ///
    void add_io_instruction_handler(
        vmcs_n::value_type port,
        io_instruction_handler::handler_delegate_t &&in_d,
        io_instruction_handler::handler_delegate_t &&out_d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Get Monitor Trap Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Monitor Trap handler stored in the vcpu if Monitor
    ///     Trap is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::monitor_trap_handler *> monitor_trap();

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a monitor-trap flag exit occurs
    ///
    void add_monitor_trap_handler(monitor_trap_handler::handler_delegate_t &&d);

    /// Enable Monitor Trap Flag
    ///
    /// @expects
    /// @ensures
    ///
    void enable_monitor_trap_flag();

    //--------------------------------------------------------------------------
    // MOV DR
    //--------------------------------------------------------------------------

    /// Get MOV DR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Move DR handler stored in the vcpu if Move DR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::mov_dr_handler *> mov_dr();

    /// Add Move DR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-dr exit occurs
    ///
    void add_mov_dr_handler(mov_dr_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Get Read MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Read MSR handler stored in the vcpu if Read MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::rdmsr_handler *> rdmsr();

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_handler_accesses();

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    void add_rdmsr_handler(
        vmcs_n::value_type msr, rdmsr_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // SIPI
    //--------------------------------------------------------------------------

    /// Get SIPI Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the sipi handler stored in the hve
    ///
    gsl::not_null<eapis::intel_x64::sipi_handler *> sipi();

    /// Add SIPI Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a SIPI exit occurs
    ///
    void add_sipi_handler(sipi_handler::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Get Write MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Write MSR handler stored in the vcpu if Write MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::wrmsr_handler *> wrmsr();

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_handler_accesses();

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    void add_wrmsr_handler(
        vmcs_n::value_type msr, wrmsr_handler::handler_delegate_t &&d);

    //==========================================================================
    // Bitmaps
    //==========================================================================

    /// MSR bitmap
    ///
    /// @expects
    /// @ensures
    ///
    /// @return A span of the msr_bitmap
    ///
    gsl::span<uint8_t> msr_bitmap();

    /// IO bitmaps
    ///
    /// @expects
    /// @ensures
    ///
    /// @return A span of the io_bitmaps
    ///
    gsl::span<uint8_t> io_bitmaps();

private:

    void check_crall();
    void check_rdcr3();
    void check_wrcr3();
    void check_rdcr8();
    void check_wrcr8();
    void check_io_bitmaps();
    void check_monitor_trap_handler();
    void check_msr_bitmap();
    void check_rdmsr_handler();
    void check_wrmsr_handler();

private:

    bool m_is_rdcr3_enabled{false};
    bool m_is_wrcr3_enabled{false};
    bool m_is_rdcr8_enabled{false};
    bool m_is_wrcr8_enabled{false};

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    std::unique_ptr<uint8_t[]> m_io_bitmaps;

    std::unique_ptr<eapis::intel_x64::ept_handler> m_ept_handler;
    std::unique_ptr<eapis::intel_x64::vpid_handler> m_vpid_handler;

    std::unique_ptr<eapis::intel_x64::control_register_handler> m_control_register_handler;
    std::unique_ptr<eapis::intel_x64::cpuid_handler> m_cpuid_handler;
    std::unique_ptr<eapis::intel_x64::ept_misconfiguration_handler> m_ept_misconfiguration_handler;
    std::unique_ptr<eapis::intel_x64::ept_violation_handler> m_ept_violation_handler;
    std::unique_ptr<eapis::intel_x64::external_interrupt_handler> m_external_interrupt_handler;
    std::unique_ptr<eapis::intel_x64::init_signal_handler> m_init_signal_handler;
    std::unique_ptr<eapis::intel_x64::interrupt_window_handler> m_interrupt_window_handler;
    std::unique_ptr<eapis::intel_x64::io_instruction_handler> m_io_instruction_handler;
    std::unique_ptr<eapis::intel_x64::monitor_trap_handler> m_monitor_trap_handler;
    std::unique_ptr<eapis::intel_x64::mov_dr_handler> m_mov_dr_handler;
    std::unique_ptr<eapis::intel_x64::rdmsr_handler> m_rdmsr_handler;
    std::unique_ptr<eapis::intel_x64::sipi_handler> m_sipi_handler;
    std::unique_ptr<eapis::intel_x64::wrmsr_handler> m_wrmsr_handler;
};

}
}

#endif
