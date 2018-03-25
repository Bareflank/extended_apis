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

#include <hve/arch/intel_x64/lapic_register.h>

namespace eapis
{
namespace intel_x64
{

namespace lapic_register
{
    std::array<attr_t, count> attributes;
}

void
init_nonexistent(uint64_t offset) noexcept
{
    auto attr = 0U;

    attr = lapic_register::xapic_readable::disable(attr);
    attr = lapic_register::xapic_writable::disable(attr);

    attr = lapic_register::x2apic_readable::disable(attr);
    attr = lapic_register::x2apic_writable::disable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_xapic_read_write(uint64_t offset) noexcept
{
    auto attr = lapic_register::attributes.at(offset);

    attr = lapic_register::x2apic_readable::disable(attr);
    attr = lapic_register::x2apic_writable::disable(attr);

    attr = lapic_register::xapic_readable::enable(attr);
    attr = lapic_register::xapic_writable::enable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_x2apic_write_only(uint64_t offset) noexcept
{
    auto attr = lapic_register::attributes.at(offset);

    attr = lapic_register::x2apic_readable::disable(attr);
    attr = lapic_register::x2apic_writable::enable(attr);

    attr = lapic_register::xapic_readable::disable(attr);
    attr = lapic_register::xapic_writable::disable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_both_write_only(uint64_t offset) noexcept
{
    auto attr = lapic_register::attributes.at(offset);

    attr = lapic_register::x2apic_readable::disable(attr);
    attr = lapic_register::x2apic_writable::enable(attr);

    attr = lapic_register::xapic_readable::disable(attr);
    attr = lapic_register::xapic_writable::enable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_both_read_only(uint64_t offset) noexcept
{
    auto attr = lapic_register::attributes.at(offset);

    attr = lapic_register::x2apic_readable::enable(attr);
    attr = lapic_register::x2apic_writable::disable(attr);

    attr = lapic_register::xapic_readable::enable(attr);
    attr = lapic_register::xapic_writable::disable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_both_read_write(uint64_t offset) noexcept
{
    auto attr = lapic_register::attributes.at(offset);

    attr = lapic_register::x2apic_readable::enable(attr);
    attr = lapic_register::x2apic_writable::enable(attr);

    attr = lapic_register::xapic_readable::enable(attr);
    attr = lapic_register::xapic_writable::enable(attr);

    lapic_register::attributes.at(offset) = attr;
}

void
init_lapic_register_attributes() noexcept
{
    using namespace ::intel_x64::msrs;
    using namespace eapis::intel_x64::lapic_register;

    const auto dfr_addr = ::intel_x64::lapic::xapic_default_base | 0x0E0U;
    const auto icr_high = ::intel_x64::lapic::xapic_default_base | 0x310U;

    for (auto i = 0U; i < lapic_register::count; i++) {
        switch (i) {
            case mem_addr_to_offset(dfr_addr):
            case mem_addr_to_offset(icr_high):
                init_xapic_read_write(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_self_ipi::addr):
                init_x2apic_write_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_eoi::addr):
                init_both_write_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_apicid::addr):
            case msr_addr_to_offset(ia32_x2apic_version::addr):
            case msr_addr_to_offset(ia32_x2apic_ppr::addr):

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

            case msr_addr_to_offset(ia32_x2apic_cur_count::addr):
                init_both_read_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_tpr::addr):
            case msr_addr_to_offset(ia32_x2apic_sivr::addr):
            case msr_addr_to_offset(ia32_x2apic_esr::addr):
            case msr_addr_to_offset(ia32_x2apic_icr::addr):

            case msr_addr_to_offset(ia32_x2apic_lvt_cmci::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_timer::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_thermal::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_pmi::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_lint0::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_lint1::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_error::addr):

            case msr_addr_to_offset(ia32_x2apic_init_count::addr):
            case msr_addr_to_offset(ia32_x2apic_div_conf::addr):
                init_both_read_write(i);
                break;

            default:
                init_nonexistent(i);
                break;
        }
    }
}

}
}
