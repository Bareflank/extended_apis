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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <arch/intel_x64/bit.h>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/apic/lapic.h>
#include <arch/intel_x64/apic/x2apic.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/apic/phys_x2apic.h>
#include <hve/arch/intel_x64/apic/virt_x2apic.h>

namespace eapis
{
namespace intel_x64
{

using namespace ::intel_x64::msrs;
namespace lapic = ::intel_x64::lapic;

///----------------------------------------------------------------------------
/// Initialization
///----------------------------------------------------------------------------

virt_x2apic::virt_x2apic(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    eapis::intel_x64::phys_x2apic *phys
) :
    m_hve{hve}
{
    this->init_registers(phys);
    this->init_interrupt_window_handler();
}

void
virt_x2apic::init_registers(eapis::intel_x64::phys_x2apic *phys)
{
    for (const auto addr : x2apic::registers) {
        if (x2apic::readable(addr)) {
            const auto val = phys->read_register(addr);
            m_reg[addr] = val;
            continue;
        }
        m_reg[addr] = 0;
    }
}

void
virt_x2apic::init_interrupt_window_handler()
{
    m_hve->add_interrupt_window_handler(
        handler_delegate_t::create<virt_x2apic,
        &virt_x2apic::handle_interrupt_window_exit>(this)
    );
}

///----------------------------------------------------------------------------
/// Register reads
///----------------------------------------------------------------------------

uint64_t
virt_x2apic::read_register(uint64_t addr) const
{ return m_reg.at(addr); }

uint64_t
virt_x2apic::read_id() const
{ return this->read_register(ia32_x2apic_apicid::addr); }

uint64_t
virt_x2apic::read_version() const
{ return this->read_register(ia32_x2apic_version::addr); }

uint64_t
virt_x2apic::read_tpr() const
{ return this->read_register(ia32_x2apic_tpr::addr); }

uint64_t
virt_x2apic::read_svr() const
{ return this->read_register(ia32_x2apic_svr::addr); }

///----------------------------------------------------------------------------
/// Register writes
///----------------------------------------------------------------------------

void
virt_x2apic::write_register(uint64_t addr, uint64_t val)
{ m_reg.at(addr) = val; }

void
virt_x2apic::write_tpr(uint64_t tpr)
{ this->write_register(ia32_x2apic_tpr::addr, tpr); }

void
virt_x2apic::write_icr(uint64_t icr)
{ this->write_register(ia32_x2apic_icr::addr, icr); }

void
virt_x2apic::write_svr(uint64_t svr)
{ this->write_register(ia32_x2apic_svr::addr, svr); }

void
virt_x2apic::write_self_ipi(uint64_t vector)
{ this->write_register(ia32_x2apic_self_ipi::addr, vector); }

void
virt_x2apic::write_eoi()
{ this->pop_isr(); }

///----------------------------------------------------------------------------
/// Interrupt injection
///----------------------------------------------------------------------------

void
virt_x2apic::queue_injection(uint64_t vector)
{
    if (m_hve->interrupt_window()->is_open()) {
        this->inject_interrupt(vector);
        return;
    }

    this->queue_interrupt(vector);
    m_hve->interrupt_window()->enable_exiting();
}

void
virt_x2apic::queue_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;
    const auto irr = ia32_x2apic_irr0::addr | ipc;

    this->write_register(irr, set_bit(this->read_register(irr), bit));
}

void
virt_x2apic::inject_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;
    const auto irr = ia32_x2apic_irr0::addr | ipc;
    const auto isr = ia32_x2apic_isr0::addr | ipc;

    this->write_register(irr, clear_bit(this->read_register(irr), bit));
    this->write_register(isr, set_bit(this->read_register(isr), bit));

    m_hve->interrupt_window()->inject(vector);
}

void
virt_x2apic::inject_spurious(uint64_t vector)
{
    if (m_hve->interrupt_window()->is_open()) {
        m_hve->interrupt_window()->inject(vector);
    }

    bfdebug_info(0, "Inject spurious denied: window closed");
}

uint64_t
virt_x2apic::top_irr()
{ return this->top_256bit(ia32_x2apic_irr7::addr); }

uint64_t
virt_x2apic::top_isr()
{ return this->top_256bit(ia32_x2apic_isr7::addr); }

uint64_t
virt_x2apic::top_256bit(uint64_t last)
{
    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto reg = this->read_register(addr);

        if (reg == 0ULL) {
            continue;
        }

        const auto msb = ::intel_x64::bit::bsr(reg);
        const auto ipc = ((7ULL - i) << 5ULL);
        return ipc | msb;
    }

    return 0U;
}

void
virt_x2apic::pop_irr()
{ this->pop_256bit(ia32_x2apic_irr7::addr); }

void
virt_x2apic::pop_isr()
{ this->pop_256bit(ia32_x2apic_isr7::addr); }

void
virt_x2apic::pop_256bit(uint64_t last)
{
    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto reg = this->read_register(addr);

        if (reg == 0ULL) {
            continue;
        }

        const auto msb = ::intel_x64::bit::bsr(reg);
        this->write_register(addr, clear_bit(reg, msb));
        return;
    }
}

bool
virt_x2apic::irr_is_empty()
{ return this->is_empty_256bit(ia32_x2apic_irr7::addr); }

bool
virt_x2apic::isr_is_empty()
{ return this->is_empty_256bit(ia32_x2apic_isr7::addr); }

bool
virt_x2apic::is_empty_256bit(uint64_t last)
{
    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto reg = this->read_register(addr);

        if (reg != 0ULL) {
            return false;
        }
    }

    return true;
}

///----------------------------------------------------------------------------
/// Exit handler
///----------------------------------------------------------------------------

bool
virt_x2apic::handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    const auto vector = this->top_irr();
    this->pop_irr();
    this->inject_interrupt(vector);

    if (this->irr_is_empty()) {
        m_hve->interrupt_window()->disable_exiting();
        return true;
    }

    m_hve->interrupt_window()->enable_exiting();
    return true;
}

}
}
