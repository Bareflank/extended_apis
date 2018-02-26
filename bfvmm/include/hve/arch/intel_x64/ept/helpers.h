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

#ifndef EPT_HELPERS_INTEL_X64_H
#define EPT_HELPERS_INTEL_X64_H

#include "memory_map.h"
#include "intrinsics.h"
#include "types.h"

// *INDENT-OFF*

namespace eapis
{
namespace intel_x64
{
namespace ept
{

/// Calculate the VMCS extended page table pointer (EPTP) field for the given
/// memory map
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
///
/// @return Returns a VMCS EPTP field
///
uint64_t eptp(memory_map &mem_map);

//--------------------------------------------------------------------------
// 1GB pages
//--------------------------------------------------------------------------

/// Map 1GB of memory from the guest physical address to host physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
///
void map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa);

/// Map 1GB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr);

/// Identity map 1GB of memory from the guest physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
///
void identity_map_1g(memory_map &mem_map, gpa_t gpa);

/// Identity map 1GB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_1g(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr);

//--------------------------------------------------------------------------
// 2MB pages
//--------------------------------------------------------------------------

/// Map 2MB of memory from the guest physical address to host physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
///
void map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa);

/// Map 2MB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr);

/// Identity map 2MB of memory from the guest physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
///
void identity_map_2m(memory_map &mem_map, gpa_t gpa);

/// Identity map 2MB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_2m(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr);

//--------------------------------------------------------------------------
// 4KB pages
//--------------------------------------------------------------------------

/// Map 4KB of memory from the guest physical address to host physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
///
void map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa);

/// Map 4KB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr);

/// Identity map 4KB of memory from the guest physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
///
void identity_map_4k(memory_map &mem_map, gpa_t gpa);

/// Identity map 4KB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_4k(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr);

/// Unmap the given guest physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
/// @param gpa the guest physical address to be unmapped
///
void unmap(memory_map &mem_map, gpa_t gpa);

}
}
}

#endif
