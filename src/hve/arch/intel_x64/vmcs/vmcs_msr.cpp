//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <gsl/gsl>

#include <util/bitmanip.h>
#include "../../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"

#include <bfvmm/memory_manager/memory_manager_x64.h>
#include <intrinsics.h>
#include <intrinsics.h>

using namespace intel_x64;
using namespace vmcs;

/// Note:
///
/// For context, here is the text from the SDM.
///
/// - Read bitmap for low MSRs (located at the MSR-bitmap address):
///   This contains one bit for each MSR address in the range 00000000H to
///   00001FFFH. The bit determines whether an execution of RDMSR applied to
///   that MSR causes a VM exit.
///
/// - Read bitmap for high MSRs (located at the MSR-bitmap address plus 1024).
///   This contains one bit for each MSR address in the range C0000000H to
///   C0001FFFH. The bit determines whether an execution of RDMSR applied to
///   that MSR causes a VM exit.
///
/// - Write bitmap for low MSRs (located at the MSR-bitmap address plus 2048).
///   This contains one bit for each MSR address in the range 00000000H to
///   00001FFFH. The bit determines whether an execution of WRMSR applied to
///   that MSR causes a VM exit.
///
/// - Write bitmap for high MSRs (located at the MSR-bitmap address plus 3072).
///   This contains one bit for each MSR address in the range C0000000H to
///   C0001FFFH. The bit determines whether an execution of WRMSR applied to
///   that MSR causes a VM exit.
///

void
vmcs_intel_x64_eapis::enable_msr_bitmap()
{
    m_msr_bitmap = std::make_unique<uint8_t[]>(x64::page_size);
    m_msr_bitmap_view = gsl::make_span(m_msr_bitmap, x64::page_size);

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
}

void
vmcs_intel_x64_eapis::disable_msr_bitmap()
{
    primary_processor_based_vm_execution_controls::use_msr_bitmap::disable();
    address_of_msr_bitmap::set(0UL);

    m_msr_bitmap_view = gsl::span<uint8_t>(nullptr);
    m_msr_bitmap.reset();
}

void
vmcs_intel_x64_eapis::trap_on_rdmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x2000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::trap_on_wrmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0x4000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x6000;
        return set_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::trap_on_all_rdmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[0], 0xFF, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::trap_on_all_wrmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[2048], 0xFF, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::pass_through_rdmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000) + 0;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x2000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::pass_through_wrmsr_access(msr_type msr)
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    if (msr <= 0x00001FFFUL)
    {
        auto &&addr = (msr - 0x00000000UL) + 0x4000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL)
    {
        auto &&addr = (msr - 0xC0000000UL) + 0x6000;
        return clear_bit_from_span(m_msr_bitmap_view, addr);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
vmcs_intel_x64_eapis::pass_through_all_rdmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[0], 0x0, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::pass_through_all_wrmsr_accesses()
{
    if (!m_msr_bitmap)
        throw std::runtime_error("msr bitmap not enabled");

    __builtin_memset(&m_msr_bitmap_view[2048], 0x0, x64::page_size / 2);
}

void
vmcs_intel_x64_eapis::whitelist_rdmsr_access(msr_list_type msrs)
{
    trap_on_all_rdmsr_accesses();
    for (auto msr : msrs)
        pass_through_rdmsr_access(msr);
}

void
vmcs_intel_x64_eapis::whitelist_wrmsr_access(msr_list_type msrs)
{
    trap_on_all_wrmsr_accesses();
    for (auto msr : msrs)
        pass_through_wrmsr_access(msr);
}

void
vmcs_intel_x64_eapis::blacklist_rdmsr_access(msr_list_type msrs)
{
    pass_through_all_rdmsr_accesses();
    for (auto msr : msrs)
        trap_on_rdmsr_access(msr);
}

void
vmcs_intel_x64_eapis::blacklist_wrmsr_access(msr_list_type msrs)
{
    pass_through_all_wrmsr_accesses();
    for (auto msr : msrs)
        trap_on_wrmsr_access(msr);
}
