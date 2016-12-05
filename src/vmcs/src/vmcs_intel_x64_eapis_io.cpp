//
// Bareflank Hypervisor Examples
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

#include <bitmanip_ext.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

void
vmcs_intel_x64_eapis::trap_on_io_access(x64::portio::port_addr_type port)
{
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
    __builtin_memset(m_io_bitmapa.get(), 0xFF, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0xFF, x64::page_size);
}

void
vmcs_intel_x64_eapis::pass_through_io_access(x64::portio::port_addr_type port)
{
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
    __builtin_memset(m_io_bitmapa.get(), 0, x64::page_size);
    __builtin_memset(m_io_bitmapb.get(), 0, x64::page_size);
}

void
vmcs_intel_x64_eapis::whitelist_io_access(const std::vector<x64::portio::port_addr_type> &ports)
{
    trap_on_all_io_accesses();
    for (auto port : ports)
        pass_through_io_access(port);
}

void
vmcs_intel_x64_eapis::blacklist_io_access(const std::vector<x64::portio::port_addr_type> &ports)
{
    pass_through_all_io_accesses();
    for (auto port : ports)
        trap_on_io_access(port);
}
