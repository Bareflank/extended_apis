//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

using namespace lapic_register;
using namespace ::intel_x64::msrs;

virt_x2apic::virt_x2apic(gsl::not_null<eapis::intel_x64::vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    this->reset_registers();
}

void
virt_x2apic::reset_registers()
{
    for (auto i = 0U; i < m_registers.size(); ++i) {
        if (lapic_register::exists_in_x2apic(i)) {
            this->reset_register(i);
        }
    }
}

uint64_t
virt_x2apic::read_register(uint64_t offset) const
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
    const auto offset = msr_addr_to_offset(ia32_x2apic_icr::addr);
    return read_register(offset);
}

void
virt_x2apic::write_register(uint64_t offset, uint64_t val)
{ m_registers.at(offset) = val; }

void
virt_x2apic::write_eoi()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_eoi::addr);
    write_register(offset, 0x0ULL);
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

///-----------------------------------------------------------------------------
/// Private
///-----------------------------------------------------------------------------

void
virt_x2apic::insert(uint64_t offset, uint64_t value)
{ m_registers.at(offset) = value; }

void
virt_x2apic::reset_id()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_apicid::addr);
    insert(offset, m_vcpu->id());
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
    val |= ::intel_x64::lapic::version::version::set(val, ::intel_x64::lapic::version::version::reset_value);
    val |= ::intel_x64::lapic::version::max_lvt_entry_minus_one::set(val, lvt_limit);
    val |= ::intel_x64::lapic::version::suppress_eoi_broadcast_supported::disable(val);

    const auto offset = msr_addr_to_offset(ia32_x2apic_version::addr);
    insert(offset, val);
}

void
virt_x2apic::reset_svr()
{
    const auto offset = msr_addr_to_offset(ia32_x2apic_sivr::addr);
    insert(offset, ::intel_x64::lapic::svr::reset_value);
}

void
virt_x2apic::reset_lvt_register(uint64_t offset)
{
    insert(offset, ::intel_x64::lapic::lvt::reset_value);
}

void
virt_x2apic::clear_register(uint64_t offset)
{ insert(offset, 0U); }

void
virt_x2apic::reset_register(uint64_t offset)
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
