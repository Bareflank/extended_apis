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

namespace eapis
{
namespace intel_x64
{
namespace ept
{

/// Calculate the VMCS extended page table pointer (EPTP) field for the given
/// memory map. The returned EPTP defaults to wb memory type with accessed and
/// dirty flags disabled.
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to calculate EPTP for
///
/// @return Returns a VMCS EPTP field
///
uint64_t eptp(memory_map &mem_map);

/// Enable EPT (and VPID if it is not enabled) using the given VMCS EPT pointer
///
/// @expects
/// @ensures
///
/// @param eptp the VMCS EPT pointer value to enable EPT with
///
void enable_ept(uint64_t eptp);

/// Disable EPT
///
/// @expects
/// @ensures
///
void disable_ept(void);

//--------------------------------------------------------------------------
// 1GB pages
//--------------------------------------------------------------------------

/// Map 1GB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map n number of contiguous 1GB page frames from the given guest physical
/// address to given host physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_n_contig_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e (inclusive)
/// to a continuous range of host physical addresses starting at hpa using 1GB
/// page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_range_1g(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map 1GB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_1g(memory_map &mem_map, gpa_t gpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map n number of contiguous 1GB page frames from the given guest
/// physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_n_contig_1g(memory_map &mem_map, gpa_t gpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using 1GB page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_range_1g(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

//--------------------------------------------------------------------------
// 2MB pages
//--------------------------------------------------------------------------

/// Map 2MB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map n number of contiguous 2MB page frames from the given guest physical
/// address to given host physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_n_contig_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e (inclusive)
/// to a continuous range of host physical addresses starting at hpa using 2MB
/// page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_range_2m(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map 2MB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_2m(memory_map &mem_map, gpa_t gpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map n number of contiguous 2MB page frames from the given guest
/// physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_n_contig_2m(memory_map &mem_map, gpa_t gpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using 2MB page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_range_2m(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

//--------------------------------------------------------------------------
// 4KB pages
//--------------------------------------------------------------------------

/// Map 4KB of memory from the guest physical address to host physical address
/// with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map n number of contiguous 4KB page frames from the given guest physical
/// address to given host physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param hpa the host physical address to map to
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_n_contig_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e (inclusive)
/// to a continuous range of host physical addresses starting at hpa using 4KB
/// page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_range_4k(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map 4KB of memory from the guest physical address with the given
/// memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_4k(memory_map &mem_map, gpa_t gpa,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map n number of contiguous 4KB page frames from the given guest
/// physical address with the given memory attributes
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to map from
/// @param n the number of contiguous pages to map
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_n_contig_4k(memory_map &mem_map, gpa_t gpa, uint64_t n,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using 4KB page frames and the given memory attributes
///
/// @expects gpa_s < gpa_e
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_range_4k(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        memory_attr_t mattr = epte::memory_attr::wb_pt);

//--------------------------------------------------------------------------
// Unmapping
//--------------------------------------------------------------------------

/// Unmap the given guest physical address
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa the guest physical address to be unmapped
///
void unmap(memory_map &mem_map, gpa_t gpa);

}
}
}

#endif
