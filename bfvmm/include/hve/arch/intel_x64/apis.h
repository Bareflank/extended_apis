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

#ifndef APIS_INTEL_X64_EAPIS_H
#define APIS_INTEL_X64_EAPIS_H

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

/// APIs
///
/// This class encapsulates the APIs into a single object that can be
/// referenced by the other APIs as needed. The Intel APIs are circular by
/// design, and as such, some APIs need to be able to use others to complete
/// their job. The class provides a simple way to solve this issue. It should
/// be noted that we don't place these APIs directly into the vCPU to prevent
/// these APIs from being coupled to the vCPU logic that is provided by the
/// based hypervisor and other extensions.
///
class apis
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs object associated with the vCPU associated with
    ///     this set of APIs.
    /// @param exit_handler the exit_handler object associated with the vCPU
    ///     associated with this set of APIs.
    ///
    apis(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL ~apis() = default;

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
    /// @return Returns the EPT handler stored in the apis if EPT is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_handler *> ept();

    /// Set EPTP
    ///
    /// Enables EPT and sets the EPTP to point to the provided mmap.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The map to set EPTP to.
    ///
    VIRTUAL void set_eptp(ept::mmap &map);

    /// Disable EPT
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_ept();

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Get VPID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID handler stored in the apis if VPID is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<vpid_handler *> vpid();

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_vpid();

    /// Disable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_vpid();

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
    /// @return Returns the CR handler stored in the apis if CR trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<control_register_handler *> control_register();

    /// Enable Write CR0 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the cr0 guest/host mask to set in the vmcs
    /// @param shadow the cr0 read shadow to set in the vmcs
    ///
    VIRTUAL void enable_wrcr0_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Write CR4 Exiting
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the cr4 guest/host mask to set in the vmcs
    /// @param shadow the cr4 read shadow to set in the vmcs
    ///
    VIRTUAL void enable_wrcr4_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr0 exit occurs
    ///
    VIRTUAL void add_wrcr0_handler(
        const control_register_handler::handler_delegate_t &d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr3 exit occurs
    ///
    VIRTUAL void add_rdcr3_handler(
        const control_register_handler::handler_delegate_t &d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr3 exit occurs
    ///
    VIRTUAL void add_wrcr3_handler(
        const control_register_handler::handler_delegate_t &d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    VIRTUAL void add_wrcr4_handler(
        const control_register_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID handler stored in the apis if CPUID trapping is
    ///     enabled, otherwise an exception is thrown
    ///
    gsl::not_null<cpuid_handler *> cpuid();

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID at the given
    ///        leaf and subleaf
    ///
    VIRTUAL void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

    /// Get EPT misconfiguration object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT misconfiguration handler stored in the apis if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_misconfiguration_handler *> ept_misconfiguration();

    /// Add EPT Misconfiguration Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_misconfiguration_handler(
        const ept_misconfiguration_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Violation
    //--------------------------------------------------------------------------

    /// Get EPT violation object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the EPT violation handler stored in the apis if EPT
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<ept_violation_handler *> ept_violation();

    /// Add EPT read violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_read_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT write violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_write_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT execute violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_execute_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

    /// Get External Interrupt Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the external interrupt handler stored in the apis if
    ///     external-interrupt exiting is enabled, otherwise an exception is
    ///     thrown
    ///
    gsl::not_null<external_interrupt_handler *> external_interrupt();

    /// Add External Interrupt Handler
    ///
    /// Turns on external interrupt handling and adds an external interrupt
    /// handler to handle external interrupts
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_external_interrupt_handler(
        const external_interrupt_handler::handler_delegate_t &d);

    /// Disable External Interrupt Support
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_external_interrupts();

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
    gsl::not_null<init_signal_handler *> init_signal();

    /// Add INIT Signal Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an INIT signal exit occurs
    ///
    VIRTUAL void add_init_signal_handler(
        const init_signal_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Get Interrupt Window Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the interrupt-window handler stored in the apis if
    ///
    gsl::not_null<interrupt_window_handler *> interrupt_window();

    /// Trap on the Next Interrupt Window
    ///
    /// When this function is called, the next time an interrupt can be
    /// safely injected into the vCPU, a VM exit will occur.
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_next_interrupt_window();

    /// Disable Interrupt Window
    ///
    /// @expects
    /// @ensures
    ///
    void disable_interrupt_window();

    /// Add Interrupt Window Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an interrupt-window exit occurs
    ///
    VIRTUAL void add_interrupt_window_handler(
        const interrupt_window_handler::handler_delegate_t &d);

    /// Is Interrupt Window Open
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if an interrupt can be injected, false otherwise.
    ///
    VIRTUAL bool is_interrupt_window_open();

    /// Inject External Interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param injects an external interrupt into the vCPU with the provided
    ///     vector
    ///
    VIRTUAL void inject_external_interrupt(uint64_t vector);

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Get IO Instruction Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the IO Instruction handler stored in the apis if IO
    ///     Instruction trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<io_instruction_handler *> io_instruction();

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
    VIRTUAL void add_io_instruction_handler(
        vmcs_n::value_type port,
        const io_instruction_handler::handler_delegate_t &in_d,
        const io_instruction_handler::handler_delegate_t &out_d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Get Monitor Trap Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Monitor Trap handler stored in the apis if Monitor
    ///     Trap is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<monitor_trap_handler *> monitor_trap();

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a monitor-trap flag exit occurs
    ///
    VIRTUAL void add_monitor_trap_handler(
        const monitor_trap_handler::handler_delegate_t &d);

    /// Enable Monitor Trap Flag
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_monitor_trap_flag();

    //--------------------------------------------------------------------------
    // MOV DR
    //--------------------------------------------------------------------------

    /// Get MOV DR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Move DR handler stored in the apis if Move DR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<mov_dr_handler *> mov_dr();

    /// Add Move DR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-dr exit occurs
    ///
    VIRTUAL void add_mov_dr_handler(
        const mov_dr_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Get Read MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Read MSR handler stored in the apis if Read MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<rdmsr_handler *> rdmsr();

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_rdmsr_handler_accesses();

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    VIRTUAL void add_rdmsr_handler(
        vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d);

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
    gsl::not_null<sipi_handler *> sipi();

    /// Add SIPI Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a SIPI exit occurs
    ///
    VIRTUAL void add_sipi_handler(
        const sipi_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Get Write MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the Write MSR handler stored in the apis if Write MSR
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<wrmsr_handler *> wrmsr();

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_wrmsr_handler_accesses();

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    VIRTUAL void add_wrmsr_handler(
        vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d);

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

    //==========================================================================
    // Resources
    //==========================================================================

    /// Add Handler Delegate
    ///
    /// Adds a handler to the handler function. When a VM exit occurs, the
    /// handler will call the delegate registered by this function as
    /// as needed. Note that the handlers are called in the reverse order they
    /// are registered (i.e. FIFO).
    ///
    /// @note If the delegate has serviced the VM exit, it should return true,
    ///     otherwise it should return false, and the next delegate registered
    ///     for this VM exit will execute, or an unimplemented exit reason
    ///     error will trigger
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_handler(
        ::intel_x64::vmcs::value_type reason,
        const handler_delegate_t &d);

private:

    void check_crall();
    void check_rdcr3();
    void check_wrcr3();
    void check_io_bitmaps();
    void check_monitor_trap_handler();
    void check_msr_bitmap();
    void check_rdmsr_handler();
    void check_wrmsr_handler();

private:

    bool m_is_rdcr3_enabled{false};
    bool m_is_wrcr3_enabled{false};

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    std::unique_ptr<uint8_t[]> m_io_bitmaps;

    std::unique_ptr<ept_handler> m_ept_handler;
    std::unique_ptr<vpid_handler> m_vpid_handler;

    std::unique_ptr<control_register_handler> m_control_register_handler;
    std::unique_ptr<cpuid_handler> m_cpuid_handler;
    std::unique_ptr<ept_misconfiguration_handler> m_ept_misconfiguration_handler;
    std::unique_ptr<ept_violation_handler> m_ept_violation_handler;
    std::unique_ptr<external_interrupt_handler> m_external_interrupt_handler;
    std::unique_ptr<init_signal_handler> m_init_signal_handler;
    std::unique_ptr<interrupt_window_handler> m_interrupt_window_handler;
    std::unique_ptr<io_instruction_handler> m_io_instruction_handler;
    std::unique_ptr<monitor_trap_handler> m_monitor_trap_handler;
    std::unique_ptr<mov_dr_handler> m_mov_dr_handler;
    std::unique_ptr<rdmsr_handler> m_rdmsr_handler;
    std::unique_ptr<sipi_handler> m_sipi_handler;
    std::unique_ptr<wrmsr_handler> m_wrmsr_handler;

    bfvmm::intel_x64::vmcs *m_vmcs;
    bfvmm::intel_x64::exit_handler *m_exit_handler;
};

}
}

#endif
