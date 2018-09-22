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

#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

apis::apis(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler,
    gsl::not_null<eapis_vcpu_state_t *> eapis_vcpu_state
) :
    m_vmcs{vmcs},
    m_exit_handler{exit_handler},

    m_msr_bitmap{static_cast<uint8_t *>(alloc_page()), free_page},
    m_io_bitmap_a{static_cast<uint8_t *>(alloc_page()), free_page},
    m_io_bitmap_b{static_cast<uint8_t *>(alloc_page()), free_page},

    m_control_register_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_cpuid_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_io_instruction_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_monitor_trap_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_mov_dr_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_rdmsr_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_wrmsr_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_xsetbv_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},

    m_ept_misconfiguration_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_ept_violation_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_external_interrupt_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_init_signal_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_interrupt_window_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_sipi_signal_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},

    m_ept_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_microcode_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()},
    m_vpid_handler{this, eapis_vcpu_state->eapis_vcpu_global_state()}
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

gsl::not_null<ept_handler *>
apis::ept()
{ return &m_ept_handler; }

void
apis::set_eptp(ept::mmap &map)
{ m_ept_handler.set_eptp(&map); }

void
apis::disable_ept()
{ m_ept_handler.set_eptp(nullptr); }

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

gsl::not_null<vpid_handler *>
apis::vpid()
{ return &m_vpid_handler; }

void
apis::enable_vpid()
{ m_vpid_handler.enable(); }

void
apis::disable_vpid()
{ m_vpid_handler.disable(); }

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

gsl::not_null<control_register_handler *>
apis::control_register()
{ return &m_control_register_handler; }

void
apis::add_wrcr0_handler(
    vmcs_n::value_type mask,
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr0_handler(d);
    m_control_register_handler.enable_wrcr0_exiting(mask);
}

void
apis::add_rdcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_rdcr3_handler(d);
    m_control_register_handler.enable_rdcr3_exiting();
}

void
apis::add_wrcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr3_handler(d);
    m_control_register_handler.enable_wrcr3_exiting();
}

void
apis::add_wrcr4_handler(
    vmcs_n::value_type mask,
    const control_register_handler::handler_delegate_t &d)
{
    m_control_register_handler.add_wrcr4_handler(d);
    m_control_register_handler.enable_wrcr4_exiting(mask);
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

gsl::not_null<cpuid_handler *>
apis::cpuid()
{ return &m_cpuid_handler; }

void
apis::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d)
{ m_cpuid_handler.add_handler(leaf, std::move(d)); }

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

gsl::not_null<ept_misconfiguration_handler *>
apis::ept_misconfiguration()
{ return &m_ept_misconfiguration_handler; }

void
apis::add_ept_misconfiguration_handler(
    const ept_misconfiguration_handler::handler_delegate_t &d)
{ m_ept_misconfiguration_handler.add_handler(d); }

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

gsl::not_null<ept_violation_handler *>
apis::ept_violation()
{ return &m_ept_violation_handler; }

void
apis::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_read_handler(d); }

void
apis::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_write_handler(d); }

void
apis::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{ m_ept_violation_handler.add_execute_handler(d); }

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

gsl::not_null<external_interrupt_handler *>
apis::external_interrupt()
{ return &m_external_interrupt_handler; }

void
apis::add_external_interrupt_handler(
    const external_interrupt_handler::handler_delegate_t &d)
{
    m_external_interrupt_handler.add_handler(d);
    m_external_interrupt_handler.enable_exiting();
}

void
apis::disable_external_interrupts()
{ m_external_interrupt_handler.disable_exiting(); }

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

gsl::not_null<interrupt_window_handler *>
apis::interrupt_window()
{ return &m_interrupt_window_handler; }

void
apis::trap_on_next_interrupt_window()
{ m_interrupt_window_handler.enable_exiting(); }

void
apis::disable_interrupt_window()
{ m_interrupt_window_handler.disable_exiting(); }

void
apis::add_interrupt_window_handler(
    const interrupt_window_handler::handler_delegate_t &d)
{ m_interrupt_window_handler.add_handler(d); }

bool
apis::is_interrupt_window_open()
{ return m_interrupt_window_handler.is_open(); }

void
apis::inject_external_interrupt(uint64_t vector)
{ m_interrupt_window_handler.inject(vector); }

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

gsl::not_null<io_instruction_handler *>
apis::io_instruction()
{ return &m_io_instruction_handler; }

void
apis::trap_all_io_instruction_accesses()
{ m_io_instruction_handler.trap_on_all_accesses(); }

void
apis::pass_through_all_io_instruction_accesses()
{ m_io_instruction_handler.pass_through_all_accesses(); }

void
apis::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    m_io_instruction_handler.trap_on_access(port);
    m_io_instruction_handler.add_handler(port, in_d, out_d);
}

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

gsl::not_null<monitor_trap_handler *>
apis::monitor_trap()
{ return &m_monitor_trap_handler; }

void
apis::add_monitor_trap_handler(
    const monitor_trap_handler::handler_delegate_t &d)
{ m_monitor_trap_handler.add_handler(d); }

void
apis::enable_monitor_trap_flag()
{ m_monitor_trap_handler.enable(); }

//--------------------------------------------------------------------------
// Move DR
//--------------------------------------------------------------------------

gsl::not_null<mov_dr_handler *>
apis::mov_dr()
{ return &m_mov_dr_handler; }

void
apis::add_mov_dr_handler(
    const mov_dr_handler::handler_delegate_t &d)
{ m_mov_dr_handler.add_handler(d); }

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

gsl::not_null<rdmsr_handler *>
apis::rdmsr()
{ return &m_rdmsr_handler; }

void
apis::trap_all_rdmsr_accesses()
{ m_rdmsr_handler.trap_on_all_accesses(); }

void
apis::pass_through_all_rdmsr_accesses()
{ m_rdmsr_handler.pass_through_all_accesses(); }

void
apis::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    m_rdmsr_handler.trap_on_access(msr);
    m_rdmsr_handler.add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

gsl::not_null<wrmsr_handler *>
apis::wrmsr()
{ return &m_wrmsr_handler; }

void
apis::trap_all_wrmsr_accesses()
{ m_wrmsr_handler.trap_on_all_accesses(); }

void
apis::pass_through_all_wrmsr_accesses()
{ m_wrmsr_handler.pass_through_all_accesses(); }

void
apis::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    m_wrmsr_handler.trap_on_access(msr);
    m_wrmsr_handler.add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// XSetBV
//----------------------------------------------------------------- ---------

gsl::not_null<xsetbv_handler *>
apis::xsetbv()
{ return &m_xsetbv_handler; }

void
apis::add_xsetbv_handler(
    const xsetbv_handler::handler_delegate_t &d)
{ m_xsetbv_handler.add_handler(std::move(d)); }

//==========================================================================
// Resources
//==========================================================================

void
apis::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, d); }

}
}
