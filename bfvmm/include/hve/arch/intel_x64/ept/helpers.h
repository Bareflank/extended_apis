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

#include "../hve.h"
#include "memory_map.h"
#include "intrinsics.h"
#include "types.h"

namespace eapis
{
namespace intel_x64
{
namespace ept
{

/// Align the given address to 1G boundary
///
/// @expects
/// @ensures
///
/// @param addr the address to align
/// @return the aligned address
///
uintptr_t align_1g(uintptr_t addr);

/// Align the given address to 2M boundary
///
/// @expects
/// @ensures
///
/// @param addr the address to align
/// @return the aligned address
///
uintptr_t align_2m(uintptr_t addr);

/// Align the given address to 4K boundary
///
/// @expects
/// @ensures
///
/// @param addr the address to align
/// @return the aligned address
///
uintptr_t align_4k(uintptr_t addr);

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

/// Enable EPT (and VPID if it is not enabled) using the given pointers
///
/// @expects
/// @ensures
///
/// @param eptp the VMCS EPT pointer value to enable EPT with
/// @param hve address of this vCPU's hve object
///
void enable_ept(uint64_t eptp, gsl::not_null<eapis::intel_x64::hve *> hve);

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
// Best fit
//--------------------------------------------------------------------------

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using as few pages as possible. This means that 1G pages
/// will be mapped from gpa_s to align_1g(gpa_e), 2M pages mapped
/// from align_1g(gpa_e) to align_2m(gpa_e), and 4K pages mapped from
/// align_2m(gpa_e) to align_4k(gpa_e).
///
/// @expects gpa_s == align_1g(gpa_s)
/// @expects gpa_s < align_4k(gpa_e)
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_bestfit_lo(ept::memory_map &mem_map, gpa_t gpa_s,
                             gpa_t gpa_e, memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using as few pages as possible. This means that 4K pages
/// will be mapped from gpa_s until the next 2M boundary, then 2M pages
/// until the next 1G boundary, then 1G pages until gpa_e
///
/// @expects align_1g(gpa_e) == gpa_e
/// @expects align_4k(gpa_s) == gpa_s
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void identity_map_bestfit_hi(ept::memory_map &mem_map, gpa_t gpa_s,
                             gpa_t gpa_e, memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) to hpa using as few pages as possible up to a maximum 2MB
/// granularity.
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_bestfit_2m(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        hpa_t hpa, memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) to hpa using as few pages as possible up to a maximum 1GB
/// granularity.
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_bestfit_1g(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        hpa_t hpa, memory_attr_t mattr = epte::memory_attr::wb_pt);

/// Map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using as few pages as possible up to the platform's largest
/// supported page size.
///
/// @expects
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
/// @param mattr page table entry memory attributes to be applied to the mapping
///
void map_bestfit(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e,
        hpa_t hpa, memory_attr_t mattr = epte::memory_attr::wb_pt);

//--------------------------------------------------------------------------
// High-level
//--------------------------------------------------------------------------

/// Map the range of guest physical addresses from gpa_s to gpa_e (inclusive)
/// using the largest page size supported by the platform and memory types that
/// are consistent with the platform's MTRRs.
///
/// @expects 
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
/// @param hpa the host physical address to map to
///
void map(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa);

/// Identity map the range of guest physical addresses from gpa_s to gpa_e
/// (inclusive) using the largest page size supported by the platform and memory
/// types that are consistent with the platform's MTRRs.
///
/// @expects 
/// @ensures
///
/// @param mem_map the memory map to be modified
/// @param gpa_s the guest physical address to start mapping from
/// @param gpa_e the guest physical address to end mapping to
///
void identity_map(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e);

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
