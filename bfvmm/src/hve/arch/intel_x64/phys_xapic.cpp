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

#include <arch/x64/rflags.h>
#include <arch/intel_x64/barrier.h>
#include <arch/intel_x64/crs.h>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/apic/lapic.h>

#include <hve/arch/intel_x64/lapic_register.h>
#include <hve/arch/intel_x64/phys_xapic.h>

namespace eapis
{
namespace intel_x64
{

static uintptr_t align_xapic(uintptr_t addr)
{ return addr & ~(x64::page_size - 1U); }

phys_xapic::phys_xapic(uintptr_t base)
{
    expects(base == align_xapic(base));
    m_base = base;
}

uintptr_t
phys_xapic::base()
{ return m_base; }

void
phys_xapic::relocate(uintptr_t base)
{
    expects(base == align_xapic(base));
    m_base = base;
}

void
phys_xapic::enable_interrupts()
{ ::x64::rflags::interrupt_enable_flag::enable(); }

void
phys_xapic::disable_interrupts()
{ ::x64::rflags::interrupt_enable_flag::disable(); }

uint64_t
phys_xapic::read_register(lapic_register::offset_t offset) const
{
    const auto addr = lapic_register::offset_to_mem_addr(offset, m_base);
    return *reinterpret_cast<uint32_t *>(addr);
}

void
phys_xapic::write_register(lapic_register::offset_t offset, uint64_t val)
{
    const volatile auto addr64 = lapic_register::offset_to_mem_addr(offset, m_base);
    const volatile auto addr32 = reinterpret_cast<uint32_t *>(addr64);

    *addr32 = gsl::narrow_cast<uint32_t>(val);
}

uint64_t
phys_xapic::read_id() const
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_apicid::addr;
    constexpr auto offset = lapic_register::msr_addr_to_offset(addr);

    return this->read_register(offset);
}

uint64_t
phys_xapic::read_version() const
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_version::addr;
    constexpr auto offset = lapic_register::msr_addr_to_offset(addr);

    return this->read_register(offset);
}

uint64_t
phys_xapic::read_tpr() const
{ return ::intel_x64::cr8::get() << 4U; }

uint64_t
phys_xapic::read_svr() const
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_sivr::addr;
    constexpr auto offset = lapic_register::msr_addr_to_offset(addr);

    return this->read_register(offset);
}

uint64_t
phys_xapic::read_icr() const
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_icr::addr;
    constexpr auto lo_offset = lapic_register::msr_addr_to_offset(addr);
    constexpr auto hi_offset = lapic_register::msr_addr_to_offset(addr | 1U);

    const auto lo = this->read_register(lo_offset);
    const auto hi = this->read_register(hi_offset);

    return (hi << 32U) | lo;
}

void
phys_xapic::write_eoi()
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_eoi::addr;
    constexpr auto offset = lapic_register::msr_addr_to_offset(addr);

    return this->write_register(offset, 0x0U);
}

void
phys_xapic::write_tpr(uint64_t tpr)
{ ::intel_x64::cr8::set(tpr >> 4U); }

void
phys_xapic::write_svr(uint64_t svr)
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_sivr::addr;
    constexpr auto offset = lapic_register::msr_addr_to_offset(addr);

    return this->write_register(offset, svr);
}

/// Note that the high 32 bits must be written first, since the interrupt
/// is fired as soon as the lower 32 are written.
void
phys_xapic::write_icr(uint64_t icr)
{
    constexpr auto addr = ::intel_x64::msrs::ia32_x2apic_icr::addr;
    constexpr auto lo_offset = lapic_register::msr_addr_to_offset(addr);
    constexpr auto hi_offset = lapic_register::msr_addr_to_offset(addr | 1U);

    const volatile uint32_t lo_val = gsl::narrow_cast<uint32_t>(icr & 0xFFFFFFFFU);
    const volatile uint32_t hi_val = gsl::narrow_cast<uint32_t>(icr >> 32U);

    this->write_register(hi_offset, hi_val);
    ::intel_x64::barrier::sfence();
    this->write_register(lo_offset, lo_val);
}

void
phys_xapic::write_self_ipi(uint64_t vector)
{
    using namespace ::intel_x64::lapic;

    auto ipi = 0ULL;
    ipi = icr::vector::set(ipi, vector);
    ipi = icr::delivery_mode::set(ipi, icr::delivery_mode::fixed);
    ipi = icr::level::enable(ipi);
    ipi = icr::trigger_mode::set(ipi, icr::trigger_mode::edge);
    ipi = icr::destination_shorthand::set(ipi, icr::destination_shorthand::self);

    this->write_icr(ipi);
}

}
}
