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

#include <vic/arch/intel_x64/lapic_register.h>
#include <vic/arch/intel_x64/phys_x2apic.h>

namespace eapis
{
namespace intel_x64
{

void
phys_x2apic::enable_interrupts()
{ ::x64::rflags::interrupt_enable_flag::enable(); }

void
phys_x2apic::disable_interrupts()
{ ::x64::rflags::interrupt_enable_flag::disable(); }

uint64_t
phys_x2apic::read_register(lapic_register::offset_t offset) const
{
    const auto addr = lapic_register::offset_to_msr_addr(offset);
    return ::intel_x64::msrs::get(addr);
}

void
phys_x2apic::write_register(lapic_register::offset_t offset, uint64_t val)
{
    const auto addr = lapic_register::offset_to_msr_addr(offset);
    return ::intel_x64::msrs::set(addr, val);
}

uint64_t
phys_x2apic::read_id() const
{ return ::intel_x64::msrs::ia32_x2apic_apicid::get(); }

uint64_t
phys_x2apic::read_version() const
{ return ::intel_x64::msrs::ia32_x2apic_version::get(); }

uint64_t
phys_x2apic::read_tpr() const
{ return ::intel_x64::msrs::ia32_x2apic_tpr::get(); }

uint64_t
phys_x2apic::read_svr() const
{ return ::intel_x64::msrs::ia32_x2apic_sivr::get(); }

uint64_t
phys_x2apic::read_icr() const
{ return ::intel_x64::msrs::ia32_x2apic_icr::get(); }

void
phys_x2apic::write_eoi()
{ ::intel_x64::msrs::ia32_x2apic_eoi::set(0x0ULL); }

void
phys_x2apic::write_tpr(uint64_t tpr)
{ ::intel_x64::msrs::ia32_x2apic_tpr::set(tpr); }

void
phys_x2apic::write_svr(uint64_t svr)
{ ::intel_x64::msrs::ia32_x2apic_sivr::set(svr); }

void
phys_x2apic::write_icr(uint64_t icr)
{ ::intel_x64::msrs::ia32_x2apic_icr::set(icr); }

void
phys_x2apic::write_self_ipi(uint64_t vector)
{ ::intel_x64::msrs::ia32_x2apic_self_ipi::set(vector); }

}
}
