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

#include <hve/arch/intel_x64/vcpu.h>
#include <vic/arch/intel_x64/lapic_register.h>
#include <vic/arch/intel_x64/virt_x2apic.h>

namespace eapis
{
namespace intel_x64
{

using namespace ::intel_x64::msrs;
using namespace lapic_register;

///----------------------------------------------------------------------------
/// Initialization
///----------------------------------------------------------------------------

virt_x2apic::virt_x2apic(gsl::not_null<eapis::intel_x64::vcpu *> vcpu) :
    m_vcpu{vcpu},
    m_interrupt_window{vcpu->interrupt_window()}
{
    reset_registers();
    init_interrupt_window_handler();
}

virt_x2apic::virt_x2apic(
    gsl::not_null<eapis::intel_x64::vcpu *> vcpu,
    gsl::not_null<eapis::intel_x64::phys_lapic *> phys) :
    m_vcpu{vcpu},
    m_interrupt_window{vcpu->interrupt_window()}
{
    init_registers_from_phys_x2apic(phys);
    init_interrupt_window_handler();
}

void
virt_x2apic::init_registers_from_phys_x2apic(
    eapis::intel_x64::phys_lapic *phys)
{
    phys->disable_interrupts();

    for (auto i = 0U; i < m_registers.size(); ++i) {
        if (lapic_register::exists_in_x2apic(i)) {
            init_virt_from_phys_x2apic(phys, i);
        }
    }

    phys->enable_interrupts();
}

void
virt_x2apic::init_virt_from_phys_x2apic(
    eapis::intel_x64::phys_lapic *phys,
    lapic_register::offset_t offset)
{
    if (lapic_register::readable_in_x2apic(offset)) {
        write_register(offset, phys->read_register(offset));
        return;
    }

    reset_register(offset);
}

void
virt_x2apic::init_interrupt_window_handler()
{
    m_interrupt_window->add_handler(
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
    return read_register(offset);
}

uint64_t
virt_x2apic::read_version() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_version::addr);
    return read_register(offset);
}

uint64_t
virt_x2apic::read_tpr() const
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_tpr::addr);
    return read_register(offset);
}

uint64_t
virt_x2apic::read_icr() const
{
    const auto offset0 = msr_addr_to_offset(ia32_x2apic_icr::addr);
    const auto offset1 = msr_addr_to_offset(ia32_x2apic_icr::addr | 1U);

    uint64_t icr = read_register(offset1) << 32U;
    icr |= read_register(offset0);

    return icr;
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
    write_register(offset, 0x0ULL);
    pop_isr();
}

void
virt_x2apic::write_tpr(uint64_t tpr)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_tpr::addr);
    write_register(offset, tpr);
}

void
virt_x2apic::write_icr(uint64_t icr)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_icr::addr);
    write_register(offset, icr);
}

void
virt_x2apic::write_self_ipi(uint64_t vector)
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_self_ipi::addr);
    write_register(offset, vector);
}

///----------------------------------------------------------------------------
/// Interrupt injection
///----------------------------------------------------------------------------

void
virt_x2apic::queue_injection(uint64_t vector)
{
    if (m_interrupt_window->is_open()) {
        inject_interrupt(vector);
        return;
    }

    queue_interrupt(vector);
    m_interrupt_window->enable_exiting();
}

void
virt_x2apic::queue_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;

    auto offset = lapic_register::msr_addr_to_offset(ia32_x2apic_irr0::addr);
    offset |= ipc;
    write_register(offset, set_bit(read_register(offset), bit));
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

    write_register(irr_offset, clear_bit(read_register(irr_offset), bit));
    write_register(isr_offset, set_bit(read_register(isr_offset), bit));

    m_interrupt_window->inject(vector);
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
{ return top_256bit(ia32_x2apic_irr7::addr); }

uint64_t
virt_x2apic::top_isr()
{ return top_256bit(ia32_x2apic_isr7::addr); }

uint64_t
virt_x2apic::top_256bit(uint64_t last)
{
    auto vector = 0U;

    for (auto i = 0U; i < 8U; ++i) {
        auto addr = last - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                auto masked_reg = (reg & (1UL << b));

                if (masked_reg != 0U) {
                    vector = ((7U - i) << 5U) | b;
                    return vector;
                }
            }
        }
    }

    return vector;
}

void
virt_x2apic::pop_irr()
{ pop_256bit(ia32_x2apic_irr7::addr); }

void
virt_x2apic::pop_isr()
{ pop_256bit(ia32_x2apic_isr7::addr); }

void
virt_x2apic::pop_256bit(uint64_t last)
{
    for (auto i = 0U; i < 8U; ++i) {
        const auto addr = last - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                auto masked_reg = (reg & (1UL << b));
                if (masked_reg != 0U) {
                    write_register(offset, clear_bit(reg, b));
                    return;
                }
            }
        }
    }
}

bool
virt_x2apic::irr_is_empty()
{
    for (auto i = 0U; i < 8U; ++i) {
        auto addr = ia32_x2apic_irr7::addr - i;
        auto offset = lapic_register::msr_addr_to_offset(addr);
        auto reg = read_register(offset);

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
    auto vector = 0U;

    inject_interrupt(vector);

    if (irr_is_empty()) {
        m_interrupt_window->disable_exiting();
        return true;
    }

    m_interrupt_window->enable_exiting();
    return true;
}

///----------------------------------------------------------------------------
/// Reset logic
///----------------------------------------------------------------------------

void
virt_x2apic::reset_registers()
{
    for (auto i = 0U; i < m_registers.size(); ++i) {
        if (lapic_register::exists_in_x2apic(i)) {
            this->reset_register(i);
        }
    }
}

void
virt_x2apic::reset_id()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_apicid::addr);
    write_register(offset, m_vcpu->id());
}

///
/// See Table 10-7 in the SDM for reference to the version reset value
///
void
virt_x2apic::reset_version()
{
    static_assert(::intel_x64::lapic::lvt::default_size > 0, "Need LVT size > 0");
    const auto lvt_limit = ::intel_x64::lapic::lvt::default_size - 1U;

    auto val = 0U;
    val |= ::intel_x64::lapic::version::version::set(val,
        ::intel_x64::lapic::version::version::reset_value);
    val |= ::intel_x64::lapic::version::max_lvt_entry_minus_one::set(val, lvt_limit);
    val |= ::intel_x64::lapic::version::suppress_eoi_broadcast_supported::disable(val);

    const auto offset = msr_addr_to_offset(ia32_x2apic_version::addr);
    write_register(offset, val);
}

void
virt_x2apic::reset_svr()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_sivr::addr);
    write_register(offset, ::intel_x64::lapic::svr::reset_value);
}

void
virt_x2apic::reset_lvt_register(lapic_register::offset_t offset)
{
    write_register(offset, ::intel_x64::lapic::lvt::reset_value);
}

void
virt_x2apic::clear_register(lapic_register::offset_t offset)
{ write_register(offset, 0U); }

void
virt_x2apic::reset_register(lapic_register::offset_t offset)
{
    switch (offset) {
        case msr_addr_to_offset(ia32_x2apic_apicid::addr):
            this->reset_id();
            break;

        case msr_addr_to_offset(ia32_x2apic_version::addr):
            this->reset_version();
            break;

        case msr_addr_to_offset(ia32_x2apic_tpr::addr):
        case msr_addr_to_offset(ia32_x2apic_ppr::addr):
        case msr_addr_to_offset(ia32_x2apic_eoi::addr):
        case msr_addr_to_offset(ia32_x2apic_ldr::addr):

        case msr_addr_to_offset(ia32_x2apic_isr0::addr):
        case msr_addr_to_offset(ia32_x2apic_isr1::addr):
        case msr_addr_to_offset(ia32_x2apic_isr2::addr):
        case msr_addr_to_offset(ia32_x2apic_isr3::addr):
        case msr_addr_to_offset(ia32_x2apic_isr4::addr):
        case msr_addr_to_offset(ia32_x2apic_isr5::addr):
        case msr_addr_to_offset(ia32_x2apic_isr6::addr):
        case msr_addr_to_offset(ia32_x2apic_isr7::addr):

        case msr_addr_to_offset(ia32_x2apic_tmr0::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr1::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr2::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr3::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr4::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr5::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr6::addr):
        case msr_addr_to_offset(ia32_x2apic_tmr7::addr):

        case msr_addr_to_offset(ia32_x2apic_irr0::addr):
        case msr_addr_to_offset(ia32_x2apic_irr1::addr):
        case msr_addr_to_offset(ia32_x2apic_irr2::addr):
        case msr_addr_to_offset(ia32_x2apic_irr3::addr):
        case msr_addr_to_offset(ia32_x2apic_irr4::addr):
        case msr_addr_to_offset(ia32_x2apic_irr5::addr):
        case msr_addr_to_offset(ia32_x2apic_irr6::addr):
        case msr_addr_to_offset(ia32_x2apic_irr7::addr):

        case msr_addr_to_offset(ia32_x2apic_esr::addr):
        case msr_addr_to_offset(ia32_x2apic_icr::addr):
        case msr_addr_to_offset(ia32_x2apic_icr::addr | 1U):
        case msr_addr_to_offset(ia32_x2apic_div_conf::addr):
        case msr_addr_to_offset(ia32_x2apic_init_count::addr):
        case msr_addr_to_offset(ia32_x2apic_cur_count::addr):
        case msr_addr_to_offset(ia32_x2apic_self_ipi::addr):
            this->clear_register(offset);
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
            bferror_info(0, "virt_x2apic: unhandled register reset");
            bferror_subnhex(0, "offset", offset);
            bferror_subnhex(0, "offset_to_msr_addr", offset_to_msr_addr(offset));

            throw std::invalid_argument(
                "virt_x2apic: unhandled register reset: " +
                std::to_string(offset)
            );

            break;
    }
}

}
}
