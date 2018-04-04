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

#ifndef MEMORY_MAP_EPT_INTEL_X64_H
#define MEMORY_MAP_EPT_INTEL_X64_H

#include <bfmemory.h>

#include "intrinsics.h"
#include "types.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// *INDENT-OFF*

namespace eapis
{
namespace intel_x64
{
namespace ept
{

/// EPT Memory Map
///
/// Provides an interface for manipulating extended page tables
///
class EXPORT_EAPIS_HVE memory_map
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    memory_map();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~memory_map();

    /// Map guest physical address to host physical address with the given
    /// page size
    ///
    /// @expects hpa aligned to size
    /// @ensures
    ///
    /// @return Returns the leaf extended page table entry that maps gpa->hpa
    ///
    /// @param gpa the guest physical address to map from
    /// @param hpa the host physical address to map to
    /// @param size the size of the page to use for this mapping
    ///
    epte_t &map(gpa_t gpa, hpa_t hpa, uint64_t size);

    /// Unmap a page by guest physical address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to unmap
    ///
    void unmap(gpa_t gpa);

    /// Guest physical address to leaf extended page table entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the leaf extended page table entry that maps gpa->hpa
    ///
    /// @param gpa the guest physical address to be converted
    ///
    epte_t &gpa_to_epte(gpa_t gpa);

    /// Guest physical address to host physical address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the host physical address that gpa is mapped to
    ///
    /// @param gpa the guest physical address to be converted
    ///
    hpa_t gpa_to_hpa(gpa_t gpa);

    /// Convert this memory maps page tables to a flat memory descriptor list.
    /// NOTE: The returned memory descriptor list does not describe memory
    /// mapped by the page tables, but rather the memory used to hold the
    /// extended page tables themselves.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return List of memory descriptors that describe the extended page
    ///     tables
    ///
    std::vector<memory_descriptor> to_mdl() const;

    /// Return the base host physical address of this memory map
    ///
    /// @expects
    /// @ensures
    ///
    /// @return This memory maps base host physical address
    ///
    hpa_t hpa() const;

#ifndef ENABLE_BUILD_TEST
private:
#endif

    /// @cond

    hva_t m_pml4_hva{0};
    hpa_t m_pml4_hpa{0};

    hpa_t allocate_page_table();
    void allocate_page_table(epte_t &entry);
    void free_page_table(epte_t &entry);
    void map_entry_to_page_frame(epte_t &entry, hpa_t hpa);

    epte_t &gpa_to_pml4e(gpa_t gpa);
    epte_t &gpa_to_pdpte(gpa_t gpa, epte_t &pml4e);
    epte_t &gpa_to_pde(gpa_t gpa, epte_t &pdpte);
    epte_t &gpa_to_pte(gpa_t gpa, epte_t &pde);

    epte_t &map_pdpte_to_page(gpa_t gpa, hpa_t hpa);
    epte_t &map_pde_to_page(gpa_t gpa, hpa_t hpa);
    epte_t &map_pte_to_page(gpa_t gpa, hpa_t hpa);

    void to_mdl(std::vector<memory_descriptor> &mdl, epte_t * page_table) const;

    /// @endcond

public:

    /// @cond

    memory_map(memory_map &&) = default;
    memory_map &operator=(memory_map &&) = default;

    memory_map(const memory_map &) = delete;
    memory_map &operator=(const memory_map &) = delete;

    /// @endcond

};

}
}
}

#endif
