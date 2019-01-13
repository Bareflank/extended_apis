//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <hve/arch/intel_x64/vcpu.h>

namespace eapis::intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    vcpu_global_state_t *vcpu_global_state
) :
    bfvmm::intel_x64::vcpu(id),

    m_vcpu_global_state{vcpu_global_state != nullptr ? vcpu_global_state : & g_vcpu_global_state},

    m_msr_bitmap{static_cast<uint8_t *>(alloc_page()), free_page},
    m_io_bitmap_a{static_cast<uint8_t *>(alloc_page()), free_page},
    m_io_bitmap_b{static_cast<uint8_t *>(alloc_page()), free_page},

    m_control_register_handler{this},
    m_cpuid_handler{this},
    m_io_instruction_handler{this},
    m_monitor_trap_handler{this},
    m_rdmsr_handler{this},
    m_wrmsr_handler{this},
    m_xsetbv_handler{this},

    m_ept_misconfiguration_handler{this},
    m_ept_violation_handler{this},
    m_external_interrupt_handler{this},
    m_init_signal_handler{this},
    m_interrupt_window_handler{this},
    m_sipi_signal_handler{this},

    m_ept_handler{this},
    m_microcode_handler{this},
    m_vpid_handler{this},
    m_preemption_timer_handler{this}
{
    using namespace vmcs_n;

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmap_a.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmap_b.get()));

    primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();

    this->enable_vpid();
}

//==========================================================================
// MISC
//==========================================================================

//--------------------------------------------------------------------------
// EPT
//--------------------------------------------------------------------------

void
vcpu::set_eptp(ept::mmap &map)
{
    m_ept_handler.set_eptp(&map);
    m_mmap = &map;
}

void
vcpu::disable_ept()
{
    m_ept_handler.set_eptp(nullptr);
    m_mmap = nullptr;
}

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

void
vcpu::enable_vpid()
{ m_vpid_handler.enable(); }

void
vcpu::disable_vpid()
{ m_vpid_handler.disable(); }

//--------------------------------------------------------------------------
// VMX preemption timer
//--------------------------------------------------------------------------

void
vcpu::enable_preemption_timer()
{ m_preemption_timer_handler.enable_exiting(); }

void
vcpu::disable_preemption_timer()
{ m_preemption_timer_handler.disable_exiting(); }

//==========================================================================
// Helpers
//==========================================================================

void
vcpu::trap_on_msr_access(vmcs_n::value_type msr)
{
    this->trap_on_rdmsr_access(msr);
    this->trap_on_wrmsr_access(msr);
}

void
vcpu::pass_through_msr_access(vmcs_n::value_type msr)
{
    this->pass_through_rdmsr_access(msr);
    this->pass_through_wrmsr_access(msr);
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

void
vcpu::add_wrcr0_handler(
    vmcs_n::value_type mask,
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr0_handler(d);
    m_control_register_handler.enable_wrcr0_exiting(mask);
}

void
vcpu::add_rdcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_rdcr3_handler(d);
    m_control_register_handler.enable_rdcr3_exiting();
}

void
vcpu::add_wrcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr3_handler(d);
    m_control_register_handler.enable_wrcr3_exiting();
}

void
vcpu::add_wrcr4_handler(
    vmcs_n::value_type mask,
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr4_handler(d);
    m_control_register_handler.enable_wrcr4_exiting(mask);
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

void
vcpu::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d)
{ m_cpuid_handler.add_handler(leaf, d); }

void
vcpu::emulate_cpuid(
    cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d)
{
    this->add_cpuid_handler(leaf, d);
    m_cpuid_handler.emulate(leaf);
}

void
vcpu::add_default_cpuid_handler(
    const ::handler_delegate_t &d)
{ m_cpuid_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

void
vcpu::add_ept_misconfiguration_handler(
    const ept_misconfiguration_handler::handler_delegate_t &d)
{ m_ept_misconfiguration_handler.add_handler(d); }

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

void
vcpu::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_read_handler(d); }

void
vcpu::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_write_handler(d); }

void
vcpu::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_execute_handler(d); }

void
vcpu::add_default_ept_read_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_read_handler(d); }

void
vcpu::add_default_ept_write_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_write_handler(d); }

void
vcpu::add_default_ept_execute_violation_handler(
    const ::handler_delegate_t &d)
{ m_ept_violation_handler.set_default_execute_handler(d); }

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

void
vcpu::add_external_interrupt_handler(
    const external_interrupt_handler::handler_delegate_t &d)
{
    m_external_interrupt_handler.add_handler(d);
    m_external_interrupt_handler.enable_exiting();
}

void
vcpu::disable_external_interrupts()
{ m_external_interrupt_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

void
vcpu::queue_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.queue_external_interrupt(vector); }

void
vcpu::inject_exception(uint64_t vector, uint64_t ec)
{ m_interrupt_window_handler.inject_exception(vector, ec); }

void
vcpu::inject_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.inject_external_interrupt(vector); }

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

void
vcpu::trap_on_all_io_instruction_accesses()
{ m_io_instruction_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_all_io_instruction_accesses()
{ m_io_instruction_handler.pass_through_all_accesses(); }

void
vcpu::pass_through_io_accesses(vmcs_n::value_type port)
{ m_io_instruction_handler.pass_through_access(port); }

void
vcpu::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    m_io_instruction_handler.trap_on_access(port);
    m_io_instruction_handler.add_handler(port, in_d, out_d);
}

void
vcpu::emulate_io_instruction(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    this->add_io_instruction_handler(port, in_d, out_d);
    m_io_instruction_handler.emulate(port);
}

void
vcpu::add_default_io_instruction_handler(
    const ::handler_delegate_t &d)
{ m_io_instruction_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

void
vcpu::add_monitor_trap_handler(
    const monitor_trap_handler::handler_delegate_t &d)
{ m_monitor_trap_handler.add_handler(d); }

void
vcpu::enable_monitor_trap_flag()
{ m_monitor_trap_handler.enable(); }

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_rdmsr_accesses()
{ m_rdmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_rdmsr_access(vmcs_n::value_type msr)
{ m_rdmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_rdmsr_accesses()
{ m_rdmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    m_rdmsr_handler.trap_on_access(msr);
    m_rdmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_rdmsr(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    this->add_rdmsr_handler(msr, d);
    m_rdmsr_handler.emulate(msr);
}

void
vcpu::add_default_rdmsr_handler(
    const ::handler_delegate_t &d)
{ m_rdmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

void
vcpu::trap_on_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.trap_on_access(msr); }

void
vcpu::trap_on_all_wrmsr_accesses()
{ m_wrmsr_handler.trap_on_all_accesses(); }

void
vcpu::pass_through_wrmsr_access(vmcs_n::value_type msr)
{ m_wrmsr_handler.pass_through_access(msr); }

void
vcpu::pass_through_all_wrmsr_accesses()
{ m_wrmsr_handler.pass_through_all_accesses(); }

void
vcpu::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    m_wrmsr_handler.trap_on_access(msr);
    m_wrmsr_handler.add_handler(msr, d);
}

void
vcpu::emulate_wrmsr(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    this->add_wrmsr_handler(msr, d);
    m_wrmsr_handler.emulate(msr);
}

void
vcpu::add_default_wrmsr_handler(
    const ::handler_delegate_t &d)
{ m_wrmsr_handler.set_default_handler(d); }

//--------------------------------------------------------------------------
// XSetBV
//--------------------------------------------------------------------------

void
vcpu::add_xsetbv_handler(
    const xsetbv_handler::handler_delegate_t &d)
{ m_xsetbv_handler.add_handler(d); }

//--------------------------------------------------------------------------
// VMX preemption timer
//--------------------------------------------------------------------------

void
vcpu::add_preemption_timer_handler(
    const preemption_timer_handler::handler_delegate_t &d)
{ m_preemption_timer_handler.add_handler(d); }

void
vcpu::set_preemption_timer(
    const preemption_timer_handler::value_t val)
{
    m_preemption_timer_handler.enable_exiting();
    m_preemption_timer_handler.set_timer(val);
}

preemption_timer_handler::value_t
vcpu::get_preemption_timer()
{ return m_preemption_timer_handler.get_timer(); }

//==============================================================================
// Memory Mapping
//==============================================================================

/// TODO
///
/// There are several things that still need to be implemented for memory
/// mapping to make this a complete set of APIs.
/// - Currently, there is no support for a 32bit guest. We currently assume
///   that CR3 is 64bit.
/// - Currently, we have a lot of support for the different page sizes, but
///   we do not handle them in the guest WRT to mapping a GVA to the VMM. We
///   only support 4k granularity.

std::pair<uintptr_t, uintptr_t>
vcpu::gpa_to_hpa(uintptr_t gpa)
{
    if (m_mmap == nullptr) {
        return {gpa, 0};
    }

    return m_mmap->virt_to_phys(gpa);
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_gpa(uint64_t gva)
{
    using namespace ::x64;
    using namespace vmcs_n;

    if (guest_cr0::paging::is_disabled()) {
        return {gva, 0};
    }

    // -------------------------------------------------------------------------
    // PML4

    auto pml4_pte =
        get_entry(bfn::upper(guest_cr3::get()), pml4::index(gva));

    if (pml4::entry::present::is_disabled(pml4_pte)) {
        throw std::runtime_error("pml4_pte is not present");
    }

    // -------------------------------------------------------------------------
    // PDPT

    auto pdpt_pte =
        get_entry(pml4::entry::phys_addr::get(pml4_pte), pdpt::index(gva));

    if (pdpt::entry::present::is_disabled(pdpt_pte)) {
        throw std::runtime_error("pdpt_pte is not present");
    }

    if (pdpt::entry::ps::is_enabled(pdpt_pte)) {
        return {
            pdpt::entry::phys_addr::get(pdpt_pte) | bfn::lower(gva, pdpt::from),
            pdpt::from
        };
    }

    // -------------------------------------------------------------------------
    // PD

    auto pd_pte =
        get_entry(pdpt::entry::phys_addr::get(pdpt_pte), pd::index(gva));

    if (pd::entry::present::is_disabled(pd_pte)) {
        throw std::runtime_error("pd_pte is not present");
    }

    if (pd::entry::ps::is_enabled(pd_pte)) {
        return {
            pd::entry::phys_addr::get(pd_pte) | bfn::lower(gva, pd::from),
            pd::from
        };
    }

    // -------------------------------------------------------------------------
    // PT

    auto pt_pte =
        get_entry(pd::entry::phys_addr::get(pd_pte), pt::index(gva));

    if (pt::entry::present::is_disabled(pt_pte)) {
        throw std::runtime_error("pt_pte is not present");
    }

    return {
        pt::entry::phys_addr::get(pt_pte) | bfn::lower(gva, pt::from),
        pt::from
    };
}

std::pair<uintptr_t, uintptr_t>
vcpu::gva_to_hpa(uint64_t gva)
{
    auto ret = this->gva_to_gpa(gva);

    if (m_mmap == nullptr) {
        return ret;
    }

    return this->gpa_to_hpa(ret.first);
}

void
vcpu::map_1g_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_2m_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_4k_ro(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_only);
}

void
vcpu::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write);
}

void
vcpu::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

void
vcpu::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{
    if (m_mmap == nullptr) {
        throw std::runtime_error("attempted map with EPT not set");
    }

    m_mmap->map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute);
}

uintptr_t
vcpu::get_entry(uintptr_t tble_gpa, std::ptrdiff_t index)
{
    auto tble = this->map_gpa_4k<uintptr_t>(tble_gpa);
    auto span = gsl::span(tble.get(), ::x64::pt::num_entries);

    return span[index];
}

}
