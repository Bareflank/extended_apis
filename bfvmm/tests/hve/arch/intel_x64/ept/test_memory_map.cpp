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

#include <support/arch/intel_x64/test_support.h>
#include "ept_test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace test_ept
{

namespace ept = eapis::intel_x64::ept;

TEST_CASE("memory_map::memory_map")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    CHECK(mem_map);
    CHECK(mem_map->m_pml4_hva != 0ULL);
}

TEST_CASE("memory_map::map")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa{0ULL};
    uintptr_t hpa{0ULL};
    uint64_t size{0ULL};
    ept::epte_t expected_entry{0ULL};
    ept::epte_t entry{0ULL};

    ept::epte::entry_type::enable(expected_entry);
    ept::epte::read_access::enable(expected_entry);
    ept::epte::write_access::enable(expected_entry);
    ept::epte::memory_type::set(expected_entry, ept::epte::memory_type::wb);

    gpa = g_unmapped_gpa;
    hpa = mock_1g_hpa;
    size = ept::pdpte::page_size_bytes;
    ept::epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0x3fffffffULL, hpa, size));

    gpa += 0x10000000000ULL;
    hpa = mock_2m_hpa;
    size = ept::pde::page_size_bytes;
    ept::epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0x1fffffULL, hpa, size));

    gpa += 0x10000000000ULL;
    hpa = mock_4k_hpa;
    size = ept::pte::page_size_bytes;
    ept::epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0xfffULL, hpa, size));

    gpa += 0x10000000000ULL;
    hpa = mock_4k_hpa;
    size = ept::pte::page_size_bytes - 1ULL;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = ept::pte::page_size_bytes + 1ULL;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = 0ULL;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = 0xffffffffffffffffULL;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
}

TEST_CASE("memory_map::unmap")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa{0ULL};
    uintptr_t hpa{0ULL};
    uint64_t size{0ULL};
    ept::epte_t entry{0ULL};

    gpa = g_mapped_gpa;
    hpa = mock_1g_hpa;
    mock_ept->add_mock_mapping(gpa, hpa);
    size = ept::pdpte::page_size_bytes;
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry != 0ULL);

    mem_map->unmap(gpa);
    CHECK_THROWS(mem_map->gpa_to_epte(gpa));
    CHECK_THROWS(mem_map->unmap(gpa));
}

TEST_CASE("memory_map::gpa_to_epte")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    // auto old_pml4 = mem_map->m_pml4_hva;
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    ept::epte_t result{0ULL};

    mock_ept->setup_mock_empty_pml4(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_mapped_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));

    mock_ept->setup_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);
    CHECK(ept::epte::is_leaf_entry(result));

    mock_ept->setup_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);
    CHECK(ept::epte::is_leaf_entry(result));

    mock_ept->setup_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);
    CHECK(ept::epte::is_leaf_entry(result));

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::hpa")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    CHECK(mem_map->hpa() == mem_map->m_pml4_hpa);
}

TEST_CASE("memory_map::allocate_page_table")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    ept::epte_t entry{0ULL};
    mem_map->allocate_page_table(entry);
    CHECK(ept::epte::read_access::is_enabled(entry));
    CHECK(ept::epte::write_access::is_enabled(entry));
    CHECK(ept::epte::execute_access::is_enabled(entry));
    CHECK(ept::epte::memory_type::get(entry) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(entry));
}

TEST_CASE("memory_map::free_page_table")
{
    MockRepository mocks;
    auto mock_ept = new ept_test_support(mocks);
    auto mem_map = new ept::memory_map();
    ept::epte_t entry{0ULL};
    mem_map->allocate_page_table(entry);
    CHECK(ept::epte::hpa(entry));
    ept::epte::read_access::enable(entry);
    ept::epte::write_access::enable(entry);
    ept::epte::ignore_pat::enable(entry);
    ept::epte::suppress_ve::enable(entry);

    mem_map->free_page_table(entry);
    CHECK(entry == 0ULL);
}

TEST_CASE("memory_map::map_entry_to_page_frame")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t test_hpa = 0x0000000ABCDEF0000ULL;

    ept::epte_t expected_entry{0ULL};
    ept::epte::set_hpa(expected_entry, test_hpa);
    ept::epte::read_access::enable(expected_entry);
    ept::epte::write_access::enable(expected_entry);
    ept::epte::memory_type::set(expected_entry, ept::epte::memory_type::wb);
    ept::epte::entry_type::enable(expected_entry);

    ept::epte_t entry{0ULL};
    mem_map->map_entry_to_page_frame(entry, test_hpa);
    CHECK(entry == expected_entry);
}

TEST_CASE("memory_map::gpa_to_pml4e")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    ept::epte_t pml4e{0ULL};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    mock_ept->setup_mock_empty_pml4(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK(pml4e == 0ULL);

    mock_ept->setup_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK(ept::epte::read_access::is_enabled(pml4e));
    CHECK(ept::epte::write_access::is_enabled(pml4e));
    CHECK(ept::epte::execute_access::is_disabled(pml4e));
    CHECK(ept::epte::hpa(pml4e) == mock_pdpt_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::gpa_to_pdpte")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    ept::epte_t pml4e{0ULL};
    ept::epte_t pdpte{0ULL};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    mock_ept->setup_mock_empty_pml4(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK_THROWS(mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e));

    mock_ept->setup_mock_1g_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    CHECK(ept::epte::read_access::is_enabled(pdpte));
    CHECK(ept::epte::write_access::is_enabled(pdpte));
    CHECK(ept::epte::execute_access::is_disabled(pdpte));
    CHECK(ept::epte::entry_type::is_enabled(pdpte));
    CHECK(ept::epte::hpa(pdpte) == mock_page_hpa);

    mock_ept->setup_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    CHECK(ept::epte::read_access::is_enabled(pdpte));
    CHECK(ept::epte::write_access::is_enabled(pdpte));
    CHECK(ept::epte::execute_access::is_disabled(pdpte));
    CHECK(ept::epte::hpa(pdpte) == mock_pd_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::gpa_to_pde")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    ept::epte_t pml4e{0ULL};
    ept::epte_t pdpte{0ULL};
    ept::epte_t pde{0ULL};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    mock_ept->setup_mock_2m_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    CHECK(ept::epte::read_access::is_enabled(pde));
    CHECK(ept::epte::write_access::is_enabled(pde));
    CHECK(ept::epte::execute_access::is_disabled(pde));
    CHECK(ept::epte::entry_type::is_enabled(pde));
    CHECK(ept::epte::hpa(pde) == mock_page_hpa);

    mock_ept->setup_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    CHECK(ept::epte::read_access::is_enabled(pde));
    CHECK(ept::epte::write_access::is_enabled(pde));
    CHECK(ept::epte::execute_access::is_disabled(pde));
    CHECK(ept::epte::hpa(pde) == mock_pt_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::gpa_to_pte")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    ept::epte_t pml4e{0ULL};
    ept::epte_t pdpte{0ULL};
    ept::epte_t pde{0ULL};
    ept::epte_t pte{0ULL};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    mock_ept->setup_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    pte = mem_map->gpa_to_pte(g_mapped_gpa, pde);
    CHECK(ept::epte::read_access::is_enabled(pte));
    CHECK(ept::epte::write_access::is_enabled(pte));
    CHECK(ept::epte::execute_access::is_disabled(pte));
    CHECK(ept::epte::entry_type::is_enabled(pte));
    CHECK(ept::epte::hpa(pte) == mock_page_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::map_pdpte_to_page")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    ept::epte_t result{0ULL};

    mock_ept->setup_mock_empty_pml4(*mem_map);
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::map_pde_to_page")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    ept::epte_t result{0ULL};

    mock_ept->setup_mock_empty_pml4(*mem_map);
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::map_pte_to_page")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    ept::epte_t result{0ULL};

    mock_ept->setup_mock_empty_pml4(*mem_map);
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->setup_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(ept::epte::read_access::is_enabled(result));
    CHECK(ept::epte::write_access::is_enabled(result));
    CHECK(ept::epte::execute_access::is_disabled(result));
    CHECK(ept::epte::entry_type::is_enabled(result));
    CHECK(ept::epte::memory_type::get(result) == ept::epte::memory_type::wb);
    CHECK(ept::epte::hpa(result) == mock_page_hpa);

    mock_ept->reset(*mem_map);
}

TEST_CASE("memory_map::to_mdl")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    mem_map->map(0xf00d0000ULL, 0ULL, ept::pte::page_size_bytes);

    auto result = mem_map->to_mdl();
    CHECK(result.size() == 4ULL);

    mem_map->map(0xbeef00000ULL, 0ULL, ept::pte::page_size_bytes);
    result = mem_map->to_mdl();
    CHECK(result.size() == 6ULL);
}

}

#endif
