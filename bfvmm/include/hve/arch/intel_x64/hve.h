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

#ifndef HVE_INTEL_X64_EAPIS_H
#define HVE_INTEL_X64_EAPIS_H

#include <bfvmm/memory_manager/memory_manager.h>

#include "control_register.h"
#include "cpuid.h"
#include "external_interrupt.h"
#include "interrupt_window.h"
#include "io_instruction.h"
#include "monitor_trap.h"
#include "mov_dr.h"
#include "rdmsr.h"
#include "vpid.h"
#include "wrmsr.h"
#include "ept.h"

namespace eapis
{
namespace intel_x64
{

/// HVE
///
/// Provides a wrapper interface around specific exit handlers,
/// as well as virtual interrupt controller (vic) functionality.
/// Users may configure the guest's exit reasons using the HVE interface.
///
class hve
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param exit_handler a pointer to the bfvmm::intel_x64::exit_handler
    /// @param vmcs a pointer to the bfvmm::intel_x64::vmcs
    ///
    hve(
        gsl::not_null<exit_handler_t *> exit_handler,
        gsl::not_null<vmcs_t *> vmcs
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~hve() = default;

public:

    /// Get Exit Handler Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the exit handler object stored in this hve
    ///
    gsl::not_null<exit_handler_t *> exit_handler();

    /// Get VMCS Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the vmcs object stored in this hve
    ///
    gsl::not_null<vmcs_t *> vmcs();

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Get Control Register Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CR object stored in the hve if CR trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::control_register *> control_register();

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
    void add_wrcr0_handler(control_register::handler_delegate_t &&d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr3 exit occurs
    ///
    void add_rdcr3_handler(control_register::handler_delegate_t &&d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr3 exit occurs
    ///
    void add_wrcr3_handler(control_register::handler_delegate_t &&d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    void add_wrcr4_handler(control_register::handler_delegate_t &&d);

    /// Add Read CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr8 exit occurs
    ///
    void add_rdcr8_handler(control_register::handler_delegate_t &&d);

    /// Add Write CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr8 exit occurs
    ///
    void add_wrcr8_handler(control_register::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID object stored in the hve if CPUID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::cpuid *> cpuid();

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param subleaf the subleaf to call d on
    /// @param d the delegate to call when the guest executes CPUID at the given
    ///        leaf and subleaf
    ///
    void add_cpuid_handler(
        cpuid::leaf_t leaf, cpuid::subleaf_t subleaf, cpuid::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

    /// Get External Interrupt Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the external interrupt object stored in the hve if
    ///     external-interrupt exiting is enabled, otherwise an exception is
    ///     thrown
    ///
    gsl::not_null<eapis::intel_x64::external_interrupt *> external_interrupt();

    /// Add External Interrupt Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param v the vector to listen to
    /// @param d the delegate to call when an exit occurs with vector v
    ///
    void add_external_interrupt_handler(
        vmcs_n::value_type v, external_interrupt::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Get Interrupt Window Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the interrupt window object stored in the hve if
    ///
    gsl::not_null<eapis::intel_x64::interrupt_window *> interrupt_window();

    /// Add Interrupt Window Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an interrupt-window exit occurs
    ///
    void add_interrupt_window_handler(interrupt_window::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Get IO Instruction Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the IO Instruction object stored in the hve if IO
    ///     Instruction trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::io_instruction *> io_instruction();

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
        io_instruction::handler_delegate_t &&in_d,
        io_instruction::handler_delegate_t &&out_d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Get Monitor Trap Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Monitor Trap object stored in the hve if Monitor
    ///     Trap is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::monitor_trap *> monitor_trap();

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a monitor-trap flag exit occurs
    ///
    void add_monitor_trap_handler(monitor_trap::handler_delegate_t &&d);

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
    /// @return Returns the Move DR object stored in the hve if Move DR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::mov_dr *> mov_dr();

    /// Add Move DR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-dr exit occurs
    ///
    void add_mov_dr_handler(mov_dr::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Get Read MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Read MSR object stored in the hve if Read MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::rdmsr *> rdmsr();

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_accesses();

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr exit occurs
    ///
    void add_rdmsr_handler(
        vmcs_n::value_type msr, rdmsr::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Get VPID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID object stored in the hve if VPID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::vpid *> vpid();

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    void enable_vpid();

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Get Write MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Write MSR object stored in the hve if Write MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::wrmsr *> wrmsr();

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_accesses();

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr exit occurs
    ///
    void add_wrmsr_handler(
        vmcs_n::value_type msr, wrmsr::handler_delegate_t &&d);

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

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

    /// Get EPT misconfiguration object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT misconfiguration object stored in the hve if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::ept_misconfiguration *> ept_misconfiguration();

    /// Add EPT Misconfiguration Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_misconfiguration_handler(
            ept_misconfiguration::handler_delegate_t &&d);

    //--------------------------------------------------------------------------
    // EPT Violation
    //--------------------------------------------------------------------------

    /// Get EPT violation object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT violation object stored in the hve if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<eapis::intel_x64::ept_violation *> ept_violation();

    /// Add EPT read violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_read_violation_handler(
            ept_violation::handler_delegate_t &&d);

    /// Add EPT write violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_write_violation_handler(
            ept_violation::handler_delegate_t &&d);

    /// Add EPT execute violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    void add_ept_execute_violation_handler(
            ept_violation::handler_delegate_t &&d);


private:

    void check_crall();
    void check_rdcr3();
    void check_wrcr3();
    void check_rdcr8();
    void check_wrcr8();
    void check_io_bitmaps();
    void check_monitor_trap();
    void check_msr_bitmap();
    void check_rdmsr();
    void check_wrmsr();

private:

    bool m_is_rdcr3_enabled{false};
    bool m_is_wrcr3_enabled{false};
    bool m_is_rdcr8_enabled{false};
    bool m_is_wrcr8_enabled{false};

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    std::unique_ptr<uint8_t[]> m_io_bitmaps;

    std::unique_ptr<eapis::intel_x64::control_register> m_control_register;
    std::unique_ptr<eapis::intel_x64::cpuid> m_cpuid;
    std::unique_ptr<eapis::intel_x64::external_interrupt> m_external_interrupt;
    std::unique_ptr<eapis::intel_x64::interrupt_window> m_interrupt_window;
    std::unique_ptr<eapis::intel_x64::io_instruction> m_io_instruction;
    std::unique_ptr<eapis::intel_x64::monitor_trap> m_monitor_trap;
    std::unique_ptr<eapis::intel_x64::mov_dr> m_mov_dr;
    std::unique_ptr<eapis::intel_x64::rdmsr> m_rdmsr;
    std::unique_ptr<eapis::intel_x64::vpid> m_vpid;
    std::unique_ptr<eapis::intel_x64::wrmsr> m_wrmsr;
    std::unique_ptr<eapis::intel_x64::ept_misconfiguration> m_ept_misconfiguration;
    std::unique_ptr<eapis::intel_x64::ept_violation> m_ept_violation;

    exit_handler_t *m_exit_handler;
    vmcs_t *m_vmcs;
};

}
}

#endif
