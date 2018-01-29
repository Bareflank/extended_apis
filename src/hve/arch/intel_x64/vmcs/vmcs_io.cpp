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
#include <hve/arch/intel_x64/vmcs/vmcs.h>

#include <bfvmm/include/memory_manager/memory_manager_x64.h>
#include <bfintrinsics/include/arch/intel_x64/vmcs/32bit_control_fields.h>
#include <bfintrinsics/include/arch/intel_x64/vmcs/64bit_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_io_bitmaps()
{
    m_io_bitmapa = std::make_unique<uint8_t[]>(x64::page_size);
    m_io_bitmapb = std::make_unique<uint8_t[]>(x64::page_size);
    m_io_bitmapa_view = gsl::make_span(m_io_bitmapa, x64::page_size);
    m_io_bitmapb_view = gsl::make_span(m_io_bitmapb, x64::page_size);

    address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(m_io_bitmapa.get()));
    address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(m_io_bitmapb.get()));

    primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
}

void
vmcs_intel_x64_eapis::disable_io_bitmaps()
{
    primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();

    address_of_io_bitmap_a::set(0UL);
    address_of_io_bitmap_b::set(0UL);

    m_io_bitmapa_view = gsl::span<uint8_t>(nullptr);
    m_io_bitmapb_view = gsl::span<uint8_t>(nullptr);
    m_io_bitmapa.reset();
    m_io_bitmapb.reset();
}

void
vmcs_intel_x64_eapis::trap_on_io_access(port_type port)
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    if (port < 0x8000)
    {
        auto &&addr = port;
        set_bit_from_span(m_io_bitmapa_view, addr);
    }
    else
    {
        auto &&addr = port - 0x8000;
        set_bit_from_span(m_io_bitmapb_view, addr);
    }
}

void
vmcs_intel_x64_eapis::trap_on_all_io_accesses()
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    __builtin_memset(m_io_bitmapa.get(), 0xFF, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0xFF, x64::page_size);
}

void
vmcs_intel_x64_eapis::pass_through_io_access(port_type port)
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    if (port < 0x8000)
    {
        auto &&addr = port;
        clear_bit_from_span(m_io_bitmapa_view, addr);
    }
    else
    {
        auto &&addr = port - 0x8000;
        clear_bit_from_span(m_io_bitmapb_view, addr);
    }
}

void
vmcs_intel_x64_eapis::pass_through_all_io_accesses()
{
    if (!m_io_bitmapa || !m_io_bitmapb)
        throw std::runtime_error("io bitmaps not enabled");

    __builtin_memset(m_io_bitmapa.get(), 0, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0, x64::page_size);
}

void
vmcs_intel_x64_eapis::whitelist_io_access(const port_list_type &ports)
{
    trap_on_all_io_accesses();
    for (auto port : ports)
        pass_through_io_access(port);
}

void
vmcs_intel_x64_eapis::blacklist_io_access(const port_list_type &ports)
{
    pass_through_all_io_accesses();
    for (auto port : ports)
        trap_on_io_access(port);
}
