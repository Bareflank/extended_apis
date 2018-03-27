//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
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
#include "hve/arch/intel_x64/ept/memory_map.h"
#include "hve/arch/intel_x64/ept/intrinsics.h"

namespace eptp = intel_x64::vmcs::ept_pointer;

namespace eapis
{
namespace intel_x64
{
namespace ept
{

uint64_t
eptp(memory_map &map)
{
    auto val = 0ULL;
    auto pml4_hpa = map.hpa();

    val = eptp::memory_type::set(val, eptp::memory_type::write_back);
    val = eptp::page_walk_length_minus_one::set(val, max_page_walk_length - 1U);
    val = eptp::accessed_and_dirty_flags::disable(val);
    val = eptp::phys_addr::set(val, pml4_hpa);

    return val;
}

void
map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa)
{ mem_map.map(gpa, hpa, pdpte::page_size_bytes); }

void
map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto entry = mem_map.map(gpa, hpa, pdpte::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
identity_map_1g(memory_map &mem_map, gpa_t gpa)
{ map_1g(mem_map, gpa, gpa); }

void
identity_map_1g(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_1g(mem_map, gpa, gpa, mattr); }

void
map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa)
{ mem_map.map(gpa, hpa, pde::page_size_bytes); }

void
map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto entry = mem_map.map(gpa, hpa, pde::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
identity_map_2m(memory_map &mem_map, gpa_t gpa)
{ map_2m(mem_map, gpa, gpa); }

void
identity_map_2m(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_2m(mem_map, gpa, gpa, mattr); }

void
map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa)
{ mem_map.map(gpa, hpa, pte::page_size_bytes); }

void
map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto entry = mem_map.map(gpa, hpa, pte::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
identity_map_4k(memory_map &mem_map, gpa_t gpa)
{ map_4k(mem_map, gpa, gpa); }

void
identity_map_4k(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_4k(mem_map, gpa, gpa, mattr); }

void
unmap(memory_map &mem_map, gpa_t gpa)
{ mem_map.unmap(gpa); }

}
}
}
