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

#ifndef EPT_TEST_SUPPORT_H
#define EPT_TEST_SUPPORT_H

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <bfvmm/memory_manager/memory_manager.h>

#include <hve/arch/intel_x64/ept.h>

namespace test_ept
{

namespace ept = eapis::intel_x64::ept;

constexpr const uintptr_t mock_pml4_hpa = 0x000ABCD000000000ULL;
constexpr const uintptr_t mock_pdpt_hpa = 0x0000000ABCD00000ULL;
constexpr const uintptr_t mock_pd_hpa = 0x0000000123400000ULL;
constexpr const uintptr_t mock_pt_hpa = 0x0000000DCBA00000ULL;
constexpr const uintptr_t mock_page_hpa = 0x000000000F00D000ULL;

constexpr const uintptr_t mock_1g_hpa = 0xFFFFC0000000ULL;
constexpr const uintptr_t mock_2m_hpa = 0xFFFFFFE00000ULL;
constexpr const uintptr_t mock_4k_hpa = 0xFFFFFFFFF000ULL;

constexpr const uintptr_t g_mapped_gpa = 0x0000FFFFFFFFF000ULL;
constexpr const uintptr_t g_unmapped_gpa = 0x0000000000000000ULL;


class ept_test_support
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mocks HippoMocks object for mocked memory manager functions
    ///
    ept_test_support(HippoMocks::MockRepository &mocks);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_test_support() = default;

    /// Add a mock host-virtual to host-physical mapping to the mock memory
    /// manager used by this test support object
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hva Host-virtual address to map from
    /// @param hpa Host-physical address to map to
    ///
    void add_mock_mapping(ept::hva_t hva, ept::hpa_t hpa);

    /// Set up the given ept memory map object with a pml4 table that contains
    /// no entries
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The ept memory map to create mocked ept page tables for
    ///
    void setup_mock_empty_pml4(ept::memory_map &map);

    /// Set up the given ept memory map object with a single 1GB page mapping,
    /// a single unamapped 1GB page table entry, and invalid EPT entries for
    /// all other page table entries in the memory map
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The ept memory map to create mocked ept page tables for
    ///
    void setup_mock_1g_page(ept::memory_map &map);

    /// Set up the given ept memory map object with a single 2MB page mapping,
    /// a single unamapped 2MB page table entry, and invalid EPT entries for
    /// all other page table entries in the memory map
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The ept memory map to create mocked ept page tables for
    ///
    void setup_mock_2m_page(ept::memory_map &map);

    /// Set up the given ept memory map object with a single 4KB page mapping,
    /// a single unamapped 4KB page table entry, and invalid EPT entries for
    /// all other page table entries in the memory map
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The ept memory map to create mocked ept page tables for
    ///
    void setup_mock_4k_page(ept::memory_map &map);

    /// Remove all mock mappings from the givem ept memory map, and reset all
    /// mock page table entries to an invalid value.
    ///
    /// NOTE: Users of the ept_test_support class must call this function
    /// before destruction of any associated ept memory objects that have been
    /// manipulated by this class.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The ept memory map to reset
    ///
    void reset(ept::memory_map &map);

private:

    uintptr_t mock_virtptr_to_physint(void *gva);
    void *mock_virtptr_to_physptr(void *gva);
    uintptr_t mock_virtint_to_physint(uintptr_t gva);
    void *mock_virtint_to_physptr(uintptr_t gva);
    void *mock_physint_to_virtptr(uintptr_t gpa);
    uintptr_t mock_physint_to_virtint(uintptr_t gpa);
    void *mock_physptr_to_virtptr(void *gpa);
    uintptr_t mock_physptr_to_virtint(void *gpa);

private:

    bfvmm::memory_manager *m_mock_mm;

    std::map<ept::hva_t, ept::hpa_t> m_mock_mem;
    volatile uintptr_t m_next_phys_addr = 0x00000000F00D0000;
    ept::hva_t m_saved_pml4_hva = 0;

    std::unique_ptr<ept::epte_t[]> m_pml4 = std::make_unique<ept::epte_t[]>(ept::page_table::num_entries);
    std::unique_ptr<ept::epte_t[]> m_pdpt = std::make_unique<ept::epte_t[]>(ept::page_table::num_entries);
    std::unique_ptr<ept::epte_t[]> m_pd = std::make_unique<ept::epte_t[]>(ept::page_table::num_entries);
    std::unique_ptr<ept::epte_t[]> m_pt = std::make_unique<ept::epte_t[]>(ept::page_table::num_entries);
    std::unique_ptr<gsl::byte[]> m_page = std::make_unique<gsl::byte[]>(ept::page_size_4k);

};

}

#endif
