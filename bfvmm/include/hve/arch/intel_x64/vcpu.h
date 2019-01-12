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

#include <bfvmm/hve/arch/intel_x64/vcpu.h>

#include "vmexit/control_register.h"
#include "vmexit/cpuid.h"
#include "vmexit/ept_misconfiguration.h"
#include "vmexit/ept_violation.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/init_signal.h"
#include "vmexit/interrupt_window.h"
#include "vmexit/io_instruction.h"
#include "vmexit/monitor_trap.h"
#include "vmexit/rdmsr.h"
#include "vmexit/sipi_signal.h"
#include "vmexit/vmx_preemption_timer.h"
#include "vmexit/wrmsr.h"
#include "vmexit/xsetbv.h"

#include "ept.h"
#include "interrupt_queue.h"
#include "lapic.h"
#include "microcode.h"
#include "vcpu_global_state.h"
#include "vpid.h"

#include "../x64/unmapper.h"

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace eapis::intel_x64
{

class vcpu :
    public bfvmm::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    /// @param vcpu_global_state a pointer to the vCPUs state
    ///
    explicit vcpu(
        vcpuid::type id,
        vcpu_global_state_t *vcpu_global_state = nullptr);

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
    // Helpers
    //==========================================================================

    /// Trap MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read/write from the provided msr will be
    /// trapped by the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap
    ///
    VIRTUAL void trap_on_msr_access(vmcs_n::value_type msr);

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read/write from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_msr_access(vmcs_n::value_type msr);

    //==========================================================================
    // VMExit
    //==========================================================================

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr0 exit occurs
    ///
    VIRTUAL void add_wrcr0_handler(
        vmcs_n::value_type mask,
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
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    VIRTUAL void add_wrcr4_handler(
        vmcs_n::value_type mask,
        const control_register_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Add CPUID Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID
    ///
    VIRTUAL void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d);

    /// Emulate CPUID
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call when the guest executes CPUID
    ///
    VIRTUAL void emulate_cpuid(
        cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d);

    /// Add CPUID Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes CPUID
    ///
    VIRTUAL void add_default_cpuid_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // EPT Misconfiguration
    //--------------------------------------------------------------------------

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

    /// Add EPT Read Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_read_violation_handler(
        const ::handler_delegate_t &d);

    /// Add EPT Write Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_write_violation_handler(
        const ::handler_delegate_t &d);

    /// Add EPT Execute Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_execute_violation_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

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
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Queue External Interrupt
    ///
    /// Queues an external interrupt for injection. If the interrupt window
    /// is open, and there are no interrupts queued for injection, the
    /// interrupt may be injected on the upcoming VM-entry, othewise the
    /// interrupt is queued, and injected when appropriate.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to queue for injection
    ///
    VIRTUAL void queue_external_interrupt(uint64_t vector);

    /// Inject General Protection Fault
    ///
    /// Queues a general protection fault (ec = 0). The injection of a GPF can
    /// occur at any time, and so no window is needed.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void inject_gpf();

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Trap All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_io_instruction_accesses();

    /// Pass Through All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_io_instruction_accesses();

    /// Pass Through Accesses
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    VIRTUAL void pass_through_io_accesses(vmcs_n::value_type port);

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

    /// Emulate IO Instruction Handler
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to call
    /// @param in_d the delegate to call when the reads in from the given port
    /// @param out_d the delegate to call when the guest writes out to the
    ///        given port.
    ///
    VIRTUAL void emulate_io_instruction(
        vmcs_n::value_type port,
        const io_instruction_handler::handler_delegate_t &in_d,
        const io_instruction_handler::handler_delegate_t &out_d);

    /// Add IO Instruction Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes an IO instruction
    ///
    VIRTUAL void add_default_io_instruction_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

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
    // Read MSR
    //--------------------------------------------------------------------------

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_rdmsr_access(vmcs_n::value_type msr);

    /// Trap All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_rdmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_rdmsr_access(vmcs_n::value_type msr);

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_rdmsr_accesses();

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

    /// Emulate Read MSR
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    VIRTUAL void emulate_rdmsr(
        vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d);

    /// Add Read MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes rdmsr
    ///
    VIRTUAL void add_default_rdmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_wrmsr_access(vmcs_n::value_type msr);

    /// Trap All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_wrmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_wrmsr_access(vmcs_n::value_type msr);

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_wrmsr_accesses();

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

    /// Emulate Write MSR
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    VIRTUAL void emulate_wrmsr(
        vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d);

    /// Add Write MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes wrmsr
    ///
    VIRTUAL void add_default_wrmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // XSetBV
    //--------------------------------------------------------------------------

    /// Add XSetBV Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a xsetbv exit occurs
    ///
    VIRTUAL void add_xsetbv_handler(
        const xsetbv_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // VMX preemption timer
    //--------------------------------------------------------------------------

    /// Add VMX preemption timer handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a VMX PET exit occurs
    ///
    VIRTUAL void add_vmx_preemption_timer_handler(
        const vmx_preemption_timer_handler::handler_delegate_t &d);

    /// Set VMX preemption timer
    ///
    /// @expects
    /// @ensures
    ///
    /// @param time the value to write to the vmcs field before
    /// the upcoming VM-entry
    ///
    VIRTUAL void set_vmx_preemption_timer(
        const vmx_preemption_timer_handler::value_t val);

    /// Get VMX preemption timer
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the VMX-preemption timer field
    ///
    VIRTUAL vmx_preemption_timer_handler::value_t get_vmx_preemption_timer();

    /// Enable VMX preemption timer exiting
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_vmx_preemption_timer();

    /// Disable VMX preemption timer exiting
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_vmx_preemption_timer();

    //==========================================================================
    // Resources
    //==========================================================================

    VIRTUAL gsl::not_null<vcpu_global_state_t *> global_state() const
    { return m_vcpu_global_state; }

    //==========================================================================
    // Memory Mapping
    //==========================================================================

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT. If EPT is not enabled, this function will return
    /// the GPA (as the HPA == the GPA), and "from" will be set to 0 as
    /// this information is not available.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gpa_to_hpa(uint64_t gpa);

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT. If EPT is not enabled, this function will return
    /// the GPA (as the HPA == the GPA), and "from" will be set to 0 as
    /// this information is not available.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gpa_to_hpa(void *gpa)
    { return gpa_to_hpa(reinterpret_cast<uintptr_t>(gpa)); }

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_gpa(uint64_t gva);

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_gpa(void *gpa)
    { return gva_to_gpa(reinterpret_cast<uintptr_t>(gpa)); }

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_hpa(uint64_t gva);

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_hpa(void *gpa)
    { return gva_to_hpa(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map 1g GPA to HPA (Read-Only)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read-Only)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read-Only)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map HPA (1g)
    ///
    /// Map a 1g host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 1g page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_1g(uintptr_t hpa)
    {
        using namespace ::x64::pdpt;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_1g(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (1g)
    ///
    /// Map a 1g host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 1g page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_1g(void *hpa)
    { return map_hpa_1g<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map HPA (2m)
    ///
    /// Map a 2m host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 2m page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_2m(uintptr_t hpa)
    {
        using namespace ::x64::pd;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_2m(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (2m)
    ///
    /// Map a 2m host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 2m page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_2m(void *hpa)
    { return map_hpa_2m<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map HPA (4k)
    ///
    /// Map a 4k host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 4k page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_4k(uintptr_t hpa)
    {
        using namespace ::x64::pt;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_4k(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (4k)
    ///
    /// Map a 4k host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 4k page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_4k(void *hpa)
    { return map_hpa_4k<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(uintptr_t gpa)
    {
        using namespace ::x64::pdpt;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_1g<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(void *gpa)
    { return map_gpa_1g<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(uintptr_t gpa)
    {
        using namespace ::x64::pd;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_2m<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(void *gpa)
    { return map_gpa_2m<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa)
    {
        using namespace ::x64::pt;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_4k<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GPA.
    ///
    /// @expects gpa != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa, std::size_t len)
    {
        using namespace ::x64::pt;

        expects(gpa != 0);
        expects(len != 0);

        auto gpa_offset = bfn::lower(gpa);
        gpa = bfn::upper(gpa);

        len *= sizeof(T);
        len += gpa_offset;
        if (bfn::lower(len) != 0) {
            len += page_size - bfn::lower(len);
        }

        auto hva = g_mm->alloc_map(len);

        for (std::size_t bytes = 0; bytes < len; bytes += page_size) {
            auto gpa_addr = gpa + bytes;
            auto hva_addr = reinterpret_cast<uintptr_t>(hva) + bytes;

            g_cr3->map_4k(hva_addr, this->gpa_to_hpa(gpa_addr).first);
        }

        return x64::unique_map<T>(
                   reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(hva) + gpa_offset),
                   x64::unmapper(hva, len)
               );
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GPA.
    ///
    /// @expects gpa != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa, std::size_t len)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa), len); }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(uintptr_t gva, std::size_t len)
    {
        using namespace ::x64::pt;

        if (vmcs_n::guest_cr0::paging::is_disabled()) {
            return map_gpa_4k<T>(gva, len);
        }

        expects(gva != 0);
        expects(len != 0);

        auto gva_offset = bfn::lower(gva);
        gva = bfn::upper(gva);

        len *= sizeof(T);
        len += gva_offset;
        if (bfn::lower(len) != 0) {
            len += page_size - bfn::lower(len);
        }

        auto hva = g_mm->alloc_map(len);

        for (auto bytes = 0ULL; bytes < len; bytes += page_size) {
            auto gva_addr = gva + bytes;
            auto hva_addr = reinterpret_cast<uintptr_t>(hva) + bytes;

            g_cr3->map_4k(hva_addr, this->gva_to_hpa(gva_addr).first);
        }

        return x64::unique_map<T>(
                   reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(hva) + gva_offset),
                   x64::unmapper(hva, len)
               );
    }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(void *gva, std::size_t len)
    { return map_gva_4k<T>(reinterpret_cast<uintptr_t>(gva), len); }

    /// Map Argument (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_arg(uintptr_t gva)
    { return map_gva_4k<T>(gva, 1); }

    /// Map Argument (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_arg(void *gva)
    { return map_gva_4k<T>(gva, 1); }

private:

    uintptr_t get_entry(uintptr_t tble_gpa, std::ptrdiff_t index);

private:

    ept::mmap *m_mmap{};
    vcpu_global_state_t *m_vcpu_global_state;

    std::unique_ptr<uint8_t, void(*)(void *)> m_msr_bitmap;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_a;
    std::unique_ptr<uint8_t, void(*)(void *)> m_io_bitmap_b;

private:

    control_register_handler m_control_register_handler;
    cpuid_handler m_cpuid_handler;
    io_instruction_handler m_io_instruction_handler;
    monitor_trap_handler m_monitor_trap_handler;
    rdmsr_handler m_rdmsr_handler;
    wrmsr_handler m_wrmsr_handler;
    xsetbv_handler m_xsetbv_handler;

    ept_misconfiguration_handler m_ept_misconfiguration_handler;
    ept_violation_handler m_ept_violation_handler;
    external_interrupt_handler m_external_interrupt_handler;
    init_signal_handler m_init_signal_handler;
    interrupt_window_handler m_interrupt_window_handler;
    sipi_signal_handler m_sipi_signal_handler;

    ept_handler m_ept_handler;
    microcode_handler m_microcode_handler;
    vpid_handler m_vpid_handler;
    vmx_preemption_timer_handler m_vmx_preemption_timer_handler;

private:

    friend class io_instruction_handler;
    friend class rdmsr_handler;
    friend class wrmsr_handler;

public:

    /// @cond

    vcpu(vcpu &&) = default;
    vcpu &operator=(vcpu &&) = default;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
};

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// Note:
//
// Undefine previously defined helper macros. Note that these are used by
// each extension to provide quick access to the vcpu in the extension. If
// include files are not handled properly, you could end up with the wrong
// vcpu, resulting in compilation errors
//

#ifdef get_vcpu
#undef get_vcpu
#endif

#ifdef vcpu_cast
#undef vcpu_cast
#endif

/// Get Guest vCPU
///
/// Gets a guest vCPU from the vCPU manager given a vcpuid
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the vCPU being queried or throws
///     and exception.
///
#define get_vcpu(a) \
    g_vcm->get<eapis::intel_x64::vcpu *>(a, __FILE__ ": invalid eapis vcpuid")

#define vcpu_cast(a) \
    static_cast<eapis::intel_x64::vcpu *>(a.get())

}

#endif
