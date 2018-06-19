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

#include <bfvmm/memory_manager/memory_manager.h>

#include <hve/arch/intel_x64/hve.h>

namespace eapis
{
namespace intel_x64
{

hve::hve(
    gsl::not_null<exit_handler_t *> exit_handler,
    gsl::not_null<vmcs_t *> vmcs
) :
    m_exit_handler{exit_handler},
    m_vmcs{vmcs}
{ }

gsl::not_null<exit_handler_t *>
hve::exit_handler()
{ return m_exit_handler; }

gsl::not_null<vmcs_t *>
hve::vmcs()
{ return m_vmcs; }

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

gsl::not_null<control_register *> hve::control_register()
{ return m_control_register.get(); }

void hve::enable_wrcr0_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register->enable_wrcr0_exiting(mask, shadow);
}

void hve::enable_wrcr4_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register->enable_wrcr4_exiting(mask, shadow);
}

void hve::add_wrcr0_handler(control_register::handler_delegate_t &&d)
{
    check_crall();
    m_control_register->add_wrcr0_handler(std::move(d));
}

void hve::add_rdcr3_handler(control_register::handler_delegate_t &&d)
{
    check_rdcr3();
    m_control_register->add_rdcr3_handler(std::move(d));
}

void hve::add_wrcr3_handler(control_register::handler_delegate_t &&d)
{
    check_wrcr3();
    m_control_register->add_wrcr3_handler(std::move(d));
}

void hve::add_wrcr4_handler(control_register::handler_delegate_t &&d)
{
    check_crall();
    m_control_register->add_wrcr4_handler(std::move(d));
}

void hve::add_rdcr8_handler(control_register::handler_delegate_t &&d)
{
    check_rdcr8();
    m_control_register->add_rdcr8_handler(std::move(d));
}

void hve::add_wrcr8_handler(control_register::handler_delegate_t &&d)
{
    check_wrcr8();
    m_control_register->add_wrcr8_handler(std::move(d));
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

gsl::not_null<cpuid *> hve::cpuid()
{ return m_cpuid.get(); }

void hve::add_cpuid_handler(
    cpuid::leaf_t leaf, cpuid::subleaf_t subleaf, cpuid::handler_delegate_t &&d)
{
    if (!m_cpuid) {
        m_cpuid = std::make_unique<eapis::intel_x64::cpuid>(this);
    }

    m_cpuid->add_handler(leaf, subleaf, std::move(d));
}

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

gsl::not_null<external_interrupt *> hve::external_interrupt()
{ return m_external_interrupt.get(); }

void hve::add_external_interrupt_handler(
    vmcs_n::value_type vector, external_interrupt::handler_delegate_t &&d)
{
    if (!m_external_interrupt) {
        m_external_interrupt =
            std::make_unique<eapis::intel_x64::external_interrupt>(this);
    }

    m_external_interrupt->add_handler(vector, std::move(d));
}

//--------------------------------------------------------------------------
// INIT Signal
//--------------------------------------------------------------------------

gsl::not_null<init_signal *> hve::init_signal()
{ return m_init_signal.get(); }

void hve::add_init_signal_handler(init_signal::handler_delegate_t &&d)
{
    if (!m_init_signal) {
        m_init_signal = std::make_unique<eapis::intel_x64::init_signal>(this);
    }

    m_init_signal->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// SIPI
//--------------------------------------------------------------------------

gsl::not_null<sipi *> hve::sipi()
{ return m_sipi.get(); }

void hve::add_sipi_handler(sipi::handler_delegate_t &&d)
{
    if (!m_sipi) {
        m_sipi = std::make_unique<eapis::intel_x64::sipi>(this);
    }

    m_sipi->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

gsl::not_null<interrupt_window *> hve::interrupt_window()
{ return m_interrupt_window.get(); }

void hve::add_interrupt_window_handler(interrupt_window::handler_delegate_t &&d)
{
    if (!m_interrupt_window) {
        m_interrupt_window =
            std::make_unique<eapis::intel_x64::interrupt_window>(this);
    }

    m_interrupt_window->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

gsl::not_null<io_instruction *> hve::io_instruction()
{ return m_io_instruction.get(); }

void hve::add_io_instruction_handler(
    vmcs_n::value_type port,
    io_instruction::handler_delegate_t &&in_d,
    io_instruction::handler_delegate_t &&out_d)
{
    check_io_bitmaps();

    if (!m_io_instruction) {
        m_io_instruction = std::make_unique<eapis::intel_x64::io_instruction>(this);
    }

    m_io_instruction->add_handler(port, std::move(in_d), std::move(out_d));
}

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

gsl::not_null<monitor_trap *> hve::monitor_trap()
{ return m_monitor_trap.get(); }

void hve::add_monitor_trap_handler(monitor_trap::handler_delegate_t &&d)
{
    check_monitor_trap();
    m_monitor_trap->add_handler(std::move(d));
}

void hve::enable_monitor_trap_flag()
{
    check_monitor_trap();
    m_monitor_trap->enable();
}

//--------------------------------------------------------------------------
// Move DR
//--------------------------------------------------------------------------

gsl::not_null<mov_dr *> hve::mov_dr()
{ return m_mov_dr.get(); }

void hve::add_mov_dr_handler(mov_dr::handler_delegate_t &&d)
{
    if (!m_mov_dr) {
        m_mov_dr = std::make_unique<eapis::intel_x64::mov_dr>(this);
    }

    m_mov_dr->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

gsl::not_null<rdmsr *> hve::rdmsr()
{ return m_rdmsr.get(); }

void hve::pass_through_all_rdmsr_accesses()
{ check_rdmsr(); }

void hve::add_rdmsr_handler(
    vmcs_n::value_type msr, rdmsr::handler_delegate_t &&d)
{
    check_rdmsr();
    m_rdmsr->add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

gsl::not_null<vpid *> hve::vpid()
{ return m_vpid.get(); }

void hve::enable_vpid()
{
    if (!m_vpid) {
        m_vpid = std::make_unique<eapis::intel_x64::vpid>();
    }
}

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

gsl::not_null<wrmsr *> hve::wrmsr()
{ return m_wrmsr.get(); }

void hve::pass_through_all_wrmsr_accesses()
{ check_wrmsr(); }

void hve::add_wrmsr_handler(
    vmcs_n::value_type msr, wrmsr::handler_delegate_t &&d)
{
    check_wrmsr();
    m_wrmsr->add_handler(msr, std::move(d));
}

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

gsl::not_null<eapis::intel_x64::ept_misconfiguration *> hve::ept_misconfiguration()
{ return m_ept_misconfiguration.get(); }

void hve::add_ept_misconfiguration_handler(
    ept_misconfiguration::handler_delegate_t &&d)
{
    if (!m_ept_misconfiguration) {
        m_ept_misconfiguration = std::make_unique<eapis::intel_x64::ept_misconfiguration>(this);
    }

    m_ept_misconfiguration->add_handler(std::move(d));
}

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

gsl::not_null<eapis::intel_x64::ept_violation *> hve::ept_violation()
{ return m_ept_violation.get(); }

void hve::add_ept_read_violation_handler(
    ept_violation::handler_delegate_t &&d)
{
    if (!m_ept_violation) {
        m_ept_violation = std::make_unique<eapis::intel_x64::ept_violation>(this);
    }

    m_ept_violation->add_read_handler(std::move(d));
}

void hve::add_ept_write_violation_handler(
    ept_violation::handler_delegate_t &&d)
{
    if (!m_ept_violation) {
        m_ept_violation = std::make_unique<eapis::intel_x64::ept_violation>(this);
    }

    m_ept_violation->add_write_handler(std::move(d));
}

void hve::add_ept_execute_violation_handler(
    ept_violation::handler_delegate_t &&d)
{
    if (!m_ept_violation) {
        m_ept_violation = std::make_unique<eapis::intel_x64::ept_violation>(this);
    }

    m_ept_violation->add_execute_handler(std::move(d));
}

//--------------------------------------------------------------------------
// Checks
//--------------------------------------------------------------------------

void hve::check_crall()
{
    if (!m_control_register) {
        m_control_register = std::make_unique<eapis::intel_x64::control_register>(this);
    }
}

void hve::check_rdcr3()
{
    check_crall();

    if (!m_is_rdcr3_enabled) {
        m_is_rdcr3_enabled = true;
        m_control_register->enable_rdcr3_exiting();
    }
}

void hve::check_wrcr3()
{
    check_crall();

    if (!m_is_wrcr3_enabled) {
        m_is_wrcr3_enabled = true;
        m_control_register->enable_wrcr3_exiting();
    }
}

void hve::check_rdcr8()
{
    check_crall();

    if (!m_is_rdcr8_enabled) {
        m_is_rdcr8_enabled = true;
        m_control_register->enable_rdcr8_exiting();
    }
}

void hve::check_wrcr8()
{
    check_crall();

    if (!m_is_wrcr8_enabled) {
        m_is_wrcr8_enabled = true;
        m_control_register->enable_wrcr8_exiting();
    }
}

void hve::check_io_bitmaps()
{
    using namespace vmcs_n;

    if (!m_io_bitmaps) {
        m_io_bitmaps = std::make_unique<uint8_t[]>(::x64::page_size * 2);

        address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(&m_io_bitmaps[0x0000]));
        address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(&m_io_bitmaps[010000]));

        primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    }
}

void hve::check_monitor_trap()
{
    if (!m_monitor_trap) {
        m_monitor_trap = std::make_unique<eapis::intel_x64::monitor_trap>(this);
    }
}

void hve::check_msr_bitmap()
{
    using namespace vmcs_n;

    if (!m_msr_bitmap) {
        m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::page_size);

        address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
        primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    }
}

void hve::check_rdmsr()
{
    check_msr_bitmap();

    if (!m_rdmsr) {
        m_rdmsr = std::make_unique<eapis::intel_x64::rdmsr>(this);
    }
}

void hve::check_wrmsr()
{
    check_msr_bitmap();

    if (!m_wrmsr) {
        m_wrmsr = std::make_unique<eapis::intel_x64::wrmsr>(this);
    }
}

gsl::span<uint8_t> hve::msr_bitmap()
{ return gsl::make_span(m_msr_bitmap.get(), ::x64::page_size); }

gsl::span<uint8_t> hve::io_bitmaps()
{ return gsl::make_span(m_io_bitmaps.get(), ::x64::page_size << 1U); }

}
}
