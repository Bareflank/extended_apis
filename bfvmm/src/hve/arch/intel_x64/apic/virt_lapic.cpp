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

#include <cstdio>
#include <arch/intel_x64/msrs.h>

#include <hve/arch/intel_x64/hve.h>
#include <arch/intel_x64/apic/lapic.h>
#include <hve/arch/intel_x64/phys_x2apic.h>
#include <hve/arch/intel_x64/vic.h>
#include <hve/arch/intel_x64/virt_lapic.h>

namespace eapis
{
namespace intel_x64
{

using namespace ::intel_x64::msrs;
namespace lapic = ::intel_x64::lapic;

///----------------------------------------------------------------------------
/// Initialization
///----------------------------------------------------------------------------

virt_lapic::virt_lapic(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    eapis::intel_x64::phys_lapic *phys
) :
    m_hve{hve}
{
    lapic::init_attributes();
    m_reg = std::make_unique<gsl::byte[]>(s_reg_bytes);
    this->init_interrupt_window_handler();

    auto x2apic = dynamic_cast<phys_x2apic *>(phys);
    if (x2apic != nullptr) {
        this->init_registers_from_phys_x2apic(x2apic);
        m_access_type = access_t::msrs;
        return;
    }

    throw std::runtime_error("virt_lapic: invalid phys_lapic");
}

virt_lapic::access_t
virt_lapic::access_type() const
{ return m_access_type; }

uintptr_t virt_lapic::base()
{ return reinterpret_cast<uintptr_t>(m_reg.get()); }

void
virt_lapic::init_registers_from_phys_x2apic(
    eapis::intel_x64::phys_x2apic *phys)
{
    for (const auto i : lapic::offset::list) {
        if (lapic::exists_in_x2apic(i)) {
            if (lapic::readable_in_x2apic(i)) {
                this->write_register(i, phys->read_register(i));
                continue;
            }
            this->reset_register(i);
            continue;
        }
        this->clear_register(i);
    }
}

void
virt_lapic::init_interrupt_window_handler()
{
    m_hve->add_interrupt_window_handler(
        handler_delegate_t::create<virt_lapic,
        &virt_lapic::handle_interrupt_window_exit>(this)
    );
}

///----------------------------------------------------------------------------
/// Register reads
///----------------------------------------------------------------------------

uint64_t
virt_lapic::read_register(lapic::offset_t offset) const
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(m_reg.get());
    const uintptr_t addr = lapic::offset::to_mem_addr(offset, base);

    return *reinterpret_cast<uint32_t *>(addr);
}

uint64_t
virt_lapic::read_id() const
{ return this->read_register(lapic::offset::id); }

uint64_t
virt_lapic::read_version() const
{ return this->read_register(lapic::offset::version); }

uint64_t
virt_lapic::read_tpr() const
{ return this->read_register(lapic::offset::tpr); }

uint64_t
virt_lapic::read_icr() const
{
    const uint64_t icr0 = this->read_register(lapic::offset::icr0);
    const uint64_t icr1 = this->read_register(lapic::offset::icr1);

    return (icr1 << 32U) | icr0;
}

uint64_t
virt_lapic::read_svr() const
{ return this->read_register(lapic::offset::svr); }

///----------------------------------------------------------------------------
/// Register writes
///----------------------------------------------------------------------------

void
virt_lapic::write_register(lapic::offset_t offset, uint64_t val)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(m_reg.get());
    const uintptr_t addr = lapic::offset::to_mem_addr(offset, base);

    *reinterpret_cast<uint32_t *>(addr) = gsl::narrow_cast<uint32_t>(val);
}

void
virt_lapic::write_eoi()
{
    this->write_register(lapic::offset::eoi, 0U);
    this->pop_isr();
}

void
virt_lapic::write_tpr(uint64_t tpr)
{ this->write_register(lapic::offset::tpr, tpr); }

void
virt_lapic::write_icr(uint64_t icr)
{
    this->write_register(lapic::offset::icr1, icr >> 32U);
    this->write_register(lapic::offset::icr0, icr & 0xFFFFFFFFU);
}

void
virt_lapic::write_self_ipi(uint64_t vector)
{ this->write_register(lapic::offset::self_ipi, vector); }

void
virt_lapic::write_svr(uint64_t svr)
{ this->write_register(lapic::offset::svr, svr); }

///----------------------------------------------------------------------------
/// Interrupt injection
///----------------------------------------------------------------------------

void
virt_lapic::queue_injection(uint64_t vector)
{
    if (m_hve->interrupt_window()->is_open()) {
        this->inject_interrupt(vector);
        return;
    }

    this->queue_interrupt(vector);
    m_hve->interrupt_window()->enable_exiting();
}

void
virt_lapic::queue_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;
    const auto offset = lapic::offset::irr0 | (ipc << 4U);

    this->write_register(offset, set_bit(this->read_register(offset), bit));
}

void
virt_lapic::inject_interrupt(uint64_t vector)
{
    const auto ipc = (vector & 0xE0U) >> 5U;
    const auto bit = (vector & 0x1FU) >> 0U;
    const auto irr_offset = lapic::offset::irr0 | (ipc << 4U);
    const auto isr_offset = lapic::offset::isr0 | (ipc << 4U);

    this->write_register(
        irr_offset, clear_bit(this->read_register(irr_offset), bit));
    this->write_register(
        isr_offset, set_bit(this->read_register(isr_offset), bit));

    m_hve->interrupt_window()->inject(vector);
}

void
virt_lapic::inject_spurious(uint64_t viv)
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
virt_lapic::top_irr()
{ return this->top_256bit(ia32_x2apic_irr7::addr); }

uint64_t
virt_lapic::top_isr()
{ return this->top_256bit(ia32_x2apic_isr7::addr); }

uint64_t
virt_lapic::top_256bit(uint64_t last)
{
    auto vector = 0ULL;

    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto offset = lapic::offset::from_msr_addr(addr);
        const auto reg = this->read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                const auto uint_b = gsl::narrow_cast<uint64_t>(b);
                const auto masked_reg = (reg & (1ULL << uint_b));

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
virt_lapic::pop_irr()
{ this->pop_256bit(ia32_x2apic_irr7::addr); }

void
virt_lapic::pop_isr()
{ this->pop_256bit(ia32_x2apic_isr7::addr); }

void
virt_lapic::pop_256bit(uint64_t last)
{
    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto offset = lapic::offset::from_msr_addr(addr);
        const auto reg = this->read_register(offset);

        if (reg) {
            for (auto b = 31; b >= 0; --b) {
                const auto masked_reg = (reg & (1ULL << gsl::narrow_cast<uint64_t>(b)));
                if (masked_reg != 0ULL) {
                    this->write_register(offset, clear_bit(reg, b));
                    return;
                }
            }
        }
    }
}

bool
virt_lapic::irr_is_empty()
{ return this->is_empty_256bit(ia32_x2apic_irr7::addr); }

bool
virt_lapic::isr_is_empty()
{ return this->is_empty_256bit(ia32_x2apic_isr7::addr); }

bool
virt_lapic::is_empty_256bit(uint64_t last)
{
    for (auto i = 0ULL; i < 8ULL; ++i) {
        const auto addr = last - i;
        const auto offset = lapic::offset::from_msr_addr(addr);
        const auto reg = this->read_register(offset);

        if (reg != 0ULL) {
            return false;
        }
    }

    return true;
}

///----------------------------------------------------------------------------
/// Exit handlers
///----------------------------------------------------------------------------

bool
virt_lapic::handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs)
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

///----------------------------------------------------------------------------
/// Reset logic
///----------------------------------------------------------------------------

void
virt_lapic::reset_registers()
{
    for (const auto i : lapic::offset::list) {
        this->reset_register(i);
    }
}

///
/// See Table 10-7 in the SDM for reference to the version reset value
///
void
virt_lapic::reset_version()
{
    using namespace ::intel_x64::lapic;

    static_assert(lvt::default_size > 0ULL, "Need LVT size > 0");
    uint64_t val = 0;

    version::version::set(val, version::version::reset_value);
    version::max_lvt_entry_minus_one::set(val, lvt::default_size - 1U);
    version::suppress_eoi_broadcast_supported::disable(val);

    this->write_register(lapic::offset::version, val);
}

void
virt_lapic::reset_svr()
{ this->write_register(lapic::offset::svr, lapic::svr::reset_value); }

void
virt_lapic::reset_lvt_register(lapic::offset_t offset)
{ this->write_register(offset, ::intel_x64::lapic::lvt::reset_value); }

void
virt_lapic::clear_register(lapic::offset_t offset)
{ this->write_register(offset, 0ULL); }

void
virt_lapic::reset_register(lapic::offset_t offset)
{
    switch (offset) {
        case lapic::offset::version:
            this->reset_version();
            break;

        case lapic::offset::lvt_cmci:
        case lapic::offset::lvt_timer:
        case lapic::offset::lvt_thermal:
        case lapic::offset::lvt_pmi:
        case lapic::offset::lvt_lint0:
        case lapic::offset::lvt_lint1:
        case lapic::offset::lvt_error:
            this->reset_lvt_register(offset);
            break;

        case lapic::offset::svr:
            this->reset_svr();
            break;

        case lapic::offset::dfr:
            this->write_register(offset, 0xFFFFFFFF);

        default:
            this->clear_register(offset);
            break;
    }
}

}
}
