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

#include <intrinsics.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/vic.h>
#include <hve/arch/intel_x64/lapic_register.h>
#include <hve/arch/intel_x64/virt_x2apic.h>

namespace eapis
{
namespace intel_x64
{

using namespace ::intel_x64::msrs;
using namespace lapic_register;

///----------------------------------------------------------------------------
/// Initialization
///----------------------------------------------------------------------------

virt_x2apic::virt_x2apic(gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_hve{hve}
{
    lapic_register::init_attributes();

    this->init_id();
    this->reset_registers();
    this->init_interrupt_window_handler();
}

virt_x2apic::virt_x2apic(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    gsl::not_null<eapis::intel_x64::phys_lapic *> phys) :
    m_hve{hve}
{
    lapic_register::init_attributes();

    this->init_id();
    this->init_registers_from_phys_x2apic(phys);
    this->init_interrupt_window_handler();
}

void
virt_x2apic::init_id()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_apicid::addr);
    this->write_register(offset, m_hve->vmcs()->save_state()->vcpuid);
}

void
virt_x2apic::init_registers_from_phys_x2apic(
    eapis::intel_x64::phys_lapic *phys)
{
    phys->disable_interrupts();

    for (auto i = 0U; i < m_registers.size(); ++i) {
        if (lapic_register::exists_in_x2apic(i)) {
            this->init_virt_from_phys_x2apic(phys, i);
            continue;
        }

        this->clear_register(i);
    }

    phys->enable_interrupts();
}

void
virt_x2apic::init_virt_from_phys_x2apic(
    eapis::intel_x64::phys_lapic *phys,
    lapic_register::offset_t offset)
{
    if (lapic_register::readable_in_x2apic(offset)) {
        this->write_register(offset, phys->read_register(offset));
        return;
    }

    this->reset_register(offset);
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
virt_x2apic::read_register(lapic_register::offset_t offset) const
{ return m_registers.at(offset); }

uint64_t
virt_x2apic::read_id() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_apicid::addr);
    return this->read_register(offset);
}

uint64_t
virt_x2apic::read_version() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_version::addr);
    return this->read_register(offset);
}

uint64_t
virt_x2apic::read_tpr() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_tpr::addr);
    return this->read_register(offset);
}

uint64_t
virt_x2apic::read_icr() const
{
    const auto icr0 = msr_addr_to_offset(ia32_x2apic_icr::addr);
    const auto icr1 = msr_addr_to_offset(ia32_x2apic_icr::addr | 1U);

    uint64_t icr = this->read_register(icr1) << 32U;
    icr |= this->read_register(icr0);

    return icr;
}

uint64_t
virt_x2apic::read_svr() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_sivr::addr);
    return this->read_register(offset);
}

///----------------------------------------------------------------------------
/// Register writes
///----------------------------------------------------------------------------

void
virt_x2apic::write_register(lapic_register::offset_t offset, uint64_t val)
{ m_registers.at(offset) = gsl::narrow_cast<uint32_t>(val); }

void
virt_x2apic::write_eoi()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_eoi::addr);
    this->write_register(offset, 0x0ULL);
    this->pop_isr();
}

void
virt_x2apic::write_tpr(uint64_t tpr)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_tpr::addr);
    this->write_register(offset, tpr);
}

void
virt_x2apic::write_icr(uint64_t icr)
{
    const auto icr0 = msr_addr_to_offset(ia32_x2apic_icr::addr);
    const auto icr1 = msr_addr_to_offset(ia32_x2apic_icr::addr | 1U);

    this->write_register(icr1, icr >> 32U);
    this->write_register(icr0, icr & 0xFFFFFFFFU);
}

void
virt_x2apic::write_self_ipi(uint64_t vector)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_self_ipi::addr);
    this->write_register(offset, vector);
}

void
virt_x2apic::write_svr(uint64_t svr)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_sivr::addr);
    this->write_register(offset, svr);
}

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

    auto offset = lapic_register::msr_addr_to_offset(ia32_x2apic_irr0::addr);
    offset |= ipc;
    this->write_register(offset, set_bit(this->read_register(offset), bit));
}

void
virt_x2apic::inject_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;

    auto irr_offset = lapic_register::msr_addr_to_offset(ia32_x2apic_irr0::addr);
    auto isr_offset = lapic_register::msr_addr_to_offset(ia32_x2apic_isr0::addr);

    irr_offset |= ipc;
    isr_offset |= ipc;

    this->write_register(irr_offset, clear_bit(this->read_register(irr_offset), bit));
    this->write_register(isr_offset, set_bit(this->read_register(isr_offset), bit));

    m_hve->interrupt_window()->inject(vector);
}

void
virt_x2apic::inject_spurious(uint64_t viv)
{
    if (m_hve->interrupt_window()->is_open()) {
        m_hve->interrupt_window()->inject(viv);
    }

    bfdebug_info(VIC_LOG_ALERT, "Inject spurious denied: interrupt window closed");
}

///----------------------------------------------------------------------------
/// 256-bit register manipulation
///
/// Note: the current implementation uses standard C++ to manipulate
/// 256-bit registers, represented as eight 32-bit values. Eventually
/// this could/should be optimized with bit-manipulation instructions
/// such as popcnt and bsr.
///----------------------------------------------------------------------------

uint64_t
virt_x2apic::top_irr()
{ return this->top_256bit(ia32_x2apic_irr7::addr); }

uint64_t
virt_x2apic::top_isr()
{ return this->top_256bit(ia32_x2apic_isr7::addr); }

uint64_t
virt_x2apic::top_256bit(uint64_t last)
{
    auto vector = 0ULL;

    for (auto i = 0U; i < 8U; ++i) {
        auto addr = last - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = this->read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                auto uint_b = gsl::narrow_cast<uint64_t>(b);
                auto masked_reg = (reg & (1ULL << uint_b));

                if (masked_reg != 0ULL) {
                    vector = ((7ULL - i) << 5ULL) | uint_b;
                    return vector;
                }
            }
        }
    }

    return vector;
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
    for (auto i = 0U; i < 8U; ++i) {
        const auto addr = last - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = this->read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                auto masked_reg = (reg & (1ULL << gsl::narrow_cast<uint64_t>(b)));
                if (masked_reg != 0ULL) {
                    this->write_register(offset, clear_bit(reg, b));
                    return;
                }
            }
        }
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
    for (auto i = 0U; i < 8U; ++i) {
        auto addr = last - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = this->read_register(offset);

        if (reg != 0U) {
            return false;
        }
    }

    return true;
}

///----------------------------------------------------------------------------
/// Exit handlers
///----------------------------------------------------------------------------

bool
virt_x2apic::handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    auto vector = this->top_irr();
    this->pop_irr();
    this->inject_interrupt(vector);

    if (irr_is_empty()) {
        m_hve->interrupt_window()->disable_exiting();
        return true;
    }

    m_hve->interrupt_window()->enable_exiting();
    return true;
}

///----------------------------------------------------------------------------
/// Reset logic
///----------------------------------------------------------------------------

void
virt_x2apic::reset_registers()
{
    for (auto i = 0U; i < m_registers.size(); ++i) {
        this->reset_register(i);
    }
}

///
/// See Table 10-7 in the SDM for reference to the version reset value
///
void
virt_x2apic::reset_version()
{
    static_assert(::intel_x64::lapic::lvt::default_size > 0ULL, "Need LVT size > 0");
    const auto lvt_limit = ::intel_x64::lapic::lvt::default_size - 1ULL;

    auto val = 0ULL;
    val |= ::intel_x64::lapic::version::version::set(val,
            ::intel_x64::lapic::version::version::reset_value);
    val |= ::intel_x64::lapic::version::max_lvt_entry_minus_one::set(val, lvt_limit);
    val |= ::intel_x64::lapic::version::suppress_eoi_broadcast_supported::disable(val);

    const auto offset = msr_addr_to_offset(ia32_x2apic_version::addr);
    this->write_register(offset, val);
}

void
virt_x2apic::reset_svr()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_sivr::addr);
    this->write_register(offset, ::intel_x64::lapic::svr::reset_value);
}

void
virt_x2apic::reset_lvt_register(lapic_register::offset_t offset)
{ this->write_register(offset, ::intel_x64::lapic::lvt::reset_value); }

void
virt_x2apic::clear_register(lapic_register::offset_t offset)
{ this->write_register(offset, 0U); }

void
virt_x2apic::reset_register(lapic_register::offset_t offset)
{
    switch (offset) {
        case msr_addr_to_offset(ia32_x2apic_version::addr):
            this->reset_version();
            break;

        case msr_addr_to_offset(ia32_x2apic_lvt_cmci::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_timer::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_thermal::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_pmi::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_lint0::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_lint1::addr):
        case msr_addr_to_offset(ia32_x2apic_lvt_error::addr):
            this->reset_lvt_register(offset);
            break;

        case msr_addr_to_offset(ia32_x2apic_sivr::addr):
            this->reset_svr();
            break;

        default:
            this->clear_register(offset);
            break;
    }
}

}
}
