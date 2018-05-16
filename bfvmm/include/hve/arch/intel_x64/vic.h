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

#include <bfcapstone.h>

#include <arch/intel_x64/apic/lapic.h>
#include <bfvmm/memory_manager/arch/x64/unique_map.h>

#include "hve.h"
#include "phys_xapic.h"
#include "phys_x2apic.h"
#include "virt_lapic.h"

#ifndef VIC_LOG_LEVELS
#define VIC_LOG_FATAL 0U
#define VIC_LOG_ERROR 1U
#define VIC_LOG_ALERT 2U
#define VIC_LOG_DEBUG 3U
#define VIC_LOG_LEVELS
#endif

namespace test
{
    class vcpu;
}

namespace eapis
{
namespace intel_x64
{

namespace ept
{
    class memory_map;
}

///-----------------------------------------------------------------------------
/// Namespace aliases
///-----------------------------------------------------------------------------

namespace apic_base = ::intel_x64::msrs::ia32_apic_base;
namespace proc_ctl1 = vmcs_n::primary_processor_based_vm_execution_controls;
namespace proc_ctl2 = vmcs_n::secondary_processor_based_vm_execution_controls;

///-----------------------------------------------------------------------------
/// Helpers
///-----------------------------------------------------------------------------

template<
    typename N,
    typename = std::enable_if_t<std::is_integral<N>::value ||
                                std::is_pointer<N>::value>>
inline void
throw_vic_fatal(const char *msg, N nhex)
{
    bferror_nhex(VIC_LOG_FATAL, msg, nhex);
    throw std::runtime_error(msg + std::to_string(nhex));
}

inline void
throw_vic_fatal(const char *msg)
{
    bferror_info(VIC_LOG_FATAL, msg);
    throw std::runtime_error(msg);
}

inline void verify_xapic_write(cs_insn *insn)
{
    expects(insn->detail != nullptr);
    expects(insn->detail->x86.op_count == 2U);

    cs_x86_op *dst = &insn->detail->x86.operands[0U];
    cs_x86_op *src = &insn->detail->x86.operands[1U];

    expects(dst->type == X86_OP_MEM);
    expects(src->type != X86_OP_FP);
}

inline void disasm_xapic_write(csh *cs, cs_insn **insn, const uint8_t *rip)
{
    expects(cs != nullptr);
    expects(insn != nullptr);
    expects(rip != nullptr);

    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, cs);

    if (err != CS_ERR_OK) {
        throw_vic_fatal("cs_open failed, err = ", static_cast<uint64_t>(err));
    }

    cs_option(*cs, CS_OPT_DETAIL, CS_OPT_ON);

    const auto need = 1U;
    const auto insn_int = reinterpret_cast<uintptr_t>(rip);
    const auto nr_bytes = vmcs_n::vm_exit_instruction_length::get();
    const auto nr_disasm = cs_disasm(*cs, rip, nr_bytes, insn_int, need, insn);

    if (nr_disasm != need) {
        throw std::runtime_error("xapic_write: expected to disasm 1 insn");
    }
}

inline uint32_t parse_written_val(
    gsl::not_null<vmcs_t *> vmcs,
    gsl::not_null<const uint8_t *> rip)
{
    csh cstone{0U};
    cs_insn *insn{nullptr};
    disasm_xapic_write(&cstone, &insn, rip);
    verify_xapic_write(insn);
    const auto src = 1U;
    const auto val = capstone::read_op_val(vmcs->save_state(), insn, src);
    free(insn);

    return val;
}

/// Virtual interrupt controller (VIC)
///
/// Provides an interface for managing physical and
/// virtual interrupts.
///
class EXPORT_EAPIS_HVE vic
{
public:

    /// Handler delegate type
    ///
    /// The delegate type clients must use when registering
    /// handlers for external-interrupt exits
    ///
    using handler_delegate_t = external_interrupt::handler_delegate_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object for this vic.
    /// @param emm the existing EPT memory map
    ///
    vic(
        gsl::not_null<eapis::intel_x64::hve *> hve,
        gsl::not_null<eapis::intel_x64::ept::memory_map *> emm);

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
    /// @param phys the physical interrupt vector
    /// @return the virtual vector corresponding to phys
    ///
    uint64_t phys_to_virt(uint64_t phys);

    /// Virtual vector to physical vector
    ///
    /// Return the _highest_priority_ physical interrupt vector the provided
    /// virtual vector maps to.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual interrupt vector
    /// @return the highest-priority physical vector corresponding to virt
    ///
    uint64_t virt_to_phys(uint64_t virt);

    ///
    /// Map
    ///
    /// Associate the virtual interrupt vector with the given
    /// physical interrupt vector
    ///
    /// @expects
    /// @ensures
    ///
    /// @param phys the physical interrupt vector
    /// @param virt the virtual interrupt vector
    ///
    void map(uint64_t phys, uint64_t virt);

    ///
    /// Unmap
    ///
    /// Disassociate the virtual interrupt vector with
    /// its highest-priority physical interrupt vector
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt the virtual interrupt vector to unmap
    ///
    void unmap(uint64_t virt);

    ///
    /// Send physical IPI
    ///
    /// Send an IPI to this physical cpu
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
    /// Queue the provided IPI for injection to this virtual cpu
    ///
    /// @note the interrupt specified by icr is subject to the
    ///       prioritization algorithm of the virtual lapic. This means
    ///       that it will not necessarily be injected on the *upcoming*
    ///       vmentry.
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
    /// @param vector the interrupt vector the handler handles
    /// @param d the delegate when an interrupt at the given vector occurs
    ///
    void add_interrupt_handler(uint64_t vector, handler_delegate_t &&d);

    /// Handle interrupt
    ///
    /// This may be invoked from an interrupt arriving via vmexit
    /// or via the physical IDT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the interrupt vector to handle
    ///
    void handle_interrupt(uint64_t vector);

    /// Handle external interrupt exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_external_interrupt_exit(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info);

    /// Handle interrupt from exit
    ///
    /// This may only be called to handle an interrupt originating via vmexit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
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
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_x2apic_read(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info);

    /// Handle x2apic write exit
    ///
    /// Handle guest attempts to write an x2apic register
    ///
    /// @expects
    /// @ensures
    //
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_x2apic_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle x2apic EOI write exit
    ///
    /// Handle guest attempts to write an EOI
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_x2apic_eoi_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

    /// Handle xAPIC write exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_xapic_write(
        gsl::not_null<vmcs_t *> vmcs, ept_violation::info_t &info);

    /// Handle cr8 read exit
    ///
    /// Handle guest attempts to read cr8
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
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
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_wrcr8(
        gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);

    /// Handle read to IA32_APIC_BASE MSR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_rdmsr_apic_base(
        gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info);

    /// Handle write to IA32_APIC_BASE MSR
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this vmexit
    /// @param info the info structure for this vmexit
    /// @return true iff the exit has been handled
    ///
    bool handle_wrmsr_apic_base(
        gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info);

private:

    static constexpr const auto s_num_vectors = 256ULL;

    void add_exit_handlers();
    void add_cr8_handlers();
    void add_lapic_handlers();
    void add_apic_base_handlers();
    void add_external_interrupt_handlers();
    void add_xapic_handlers();
    void add_x2apic_handlers();
    void add_x2apic_read_handler(::intel_x64::lapic::offset_t offset);
    void add_x2apic_write_handler(::intel_x64::lapic::offset_t offset);

    void init_idt();
    void init_lapic();
    void init_phys_xapic();
    void init_phys_x2apic();
    void init_virt_lapic();
    void init_save_state();
    void init_interrupt_map();

    bool handle_spurious_interrupt(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info);

    uint64_t m_virt_base_msr;
    uint64_t m_phys_base_msr;
    const uint64_t m_orig_base_msr;

    eapis::intel_x64::hve *m_hve;
    eapis::intel_x64::ept::memory_map *m_emm;

    std::array<uint8_t, s_num_vectors> m_interrupt_map;
    std::array<std::list<handler_delegate_t>, s_num_vectors> m_handlers;
    alignas(0x1000) std::array<uint32_t, ::intel_x64::lapic::count> m_virt_lapic_regs;

    std::unique_ptr<gsl::byte[]> m_ist1;
    std::unique_ptr<eapis::intel_x64::virt_lapic> m_virt_lapic;
    std::unique_ptr<eapis::intel_x64::phys_lapic> m_phys_lapic;

    bfvmm::x64::unique_map_ptr<uint8_t> m_xapic_ump;
    std::unordered_map<uintptr_t, bfvmm::x64::unique_map_ptr<uint8_t>> m_write_cache;

    friend class test::vcpu;

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
