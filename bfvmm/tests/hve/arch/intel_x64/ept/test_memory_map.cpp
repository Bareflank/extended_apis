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

#include "ept_test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{
namespace ept
{

TEST_CASE("memory_map::memory_map")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();

    CHECK(mem_map);
    CHECK(mem_map->m_pml4_hva != 0);
}

TEST_CASE("memory_map::~memory_map")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    delete mem_map;
}

TEST_CASE("memory_map::map")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa{0};
    uintptr_t hpa{0};
    uint64_t size{0};
    epte_t entry{0};
    epte_t expected_entry{0};
    epte::entry_type::enable(expected_entry);
    epte::read_access::enable(expected_entry);
    epte::write_access::enable(expected_entry);
    epte::memory_type::set(expected_entry, epte::memory_type::wb);

    gpa = g_unmapped_gpa;
    hpa = mock_1g_hpa;
    size = ept::pdpte::page_size_bytes;
    epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0x3fffffff, hpa, size));

    gpa += 0x10000000000;
    hpa = mock_2m_hpa;
    size = ept::pde::page_size_bytes;
    epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0x1fffff, hpa, size));

    gpa += 0x10000000000;
    hpa = mock_4k_hpa;
    size = ept::pte::page_size_bytes;
    epte::set_hpa(expected_entry, hpa);
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry == expected_entry);
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    CHECK_THROWS(mem_map->map(gpa + 0xfff, hpa, size));

    gpa += 0x10000000000;
    hpa = mock_4k_hpa;
    size = ept::pte::page_size_bytes - 1;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = ept::pte::page_size_bytes + 1;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = 0;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
    size = 0xffffffffffffffff;
    CHECK_THROWS(mem_map->map(gpa, hpa, size));
}

TEST_CASE("memory_map::unmap")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa{0};
    uintptr_t hpa{0};
    uint64_t size{0};
    epte_t entry{0};

    gpa = g_mapped_gpa;
    hpa = mock_1g_hpa;
    g_mock_mem[reinterpret_cast<void *>(gpa)] = hpa;
    size = ept::pdpte::page_size_bytes;
    entry = mem_map->map(gpa, hpa, size);
    CHECK(entry != 0);

    mem_map->unmap(gpa);
    CHECK_THROWS(mem_map->gpa_to_epte(gpa));
    CHECK_THROWS(mem_map->unmap(gpa));

    g_mock_mem.clear();
}

TEST_CASE("memory_map::gpa_to_epte")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    epte_t result{0};

    allocate_mock_empty_pml4(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_mapped_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    free_mock_tables();

    allocate_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(epte::hpa(result) == mock_page_hpa);
    CHECK(epte::is_leaf_entry(result));
    free_mock_tables();

    allocate_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(epte::hpa(result) == mock_page_hpa);
    CHECK(epte::is_leaf_entry(result));
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->gpa_to_epte(g_unmapped_gpa));
    result = mem_map->gpa_to_epte(g_mapped_gpa);
    CHECK(epte::hpa(result) == mock_page_hpa);
    CHECK(epte::is_leaf_entry(result));
    free_mock_tables();
}

TEST_CASE("memory_map::hpa")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();

    CHECK(mem_map->hpa() == mem_map->m_pml4_hpa);
}

TEST_CASE("memory_map::allocate_page_table")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();

    epte_t entry{0};
    mem_map->allocate_page_table(entry);
    CHECK(epte::read_access::is_enabled(entry));
    CHECK(epte::write_access::is_enabled(entry));
    CHECK(epte::execute_access::is_enabled(entry));
    CHECK(epte::memory_type::get(entry) == epte::memory_type::wb);
    CHECK(epte::hpa(entry));
}

TEST_CASE("memory_map::free_page_table")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    epte_t entry{0};
    mem_map->allocate_page_table(entry);
    CHECK(epte::hpa(entry));
    epte::read_access::enable(entry);
    epte::write_access::enable(entry);
    epte::ignore_pat::enable(entry);
    epte::suppress_ve::enable(entry);

    mem_map->free_page_table(entry);
    CHECK(entry == 0);
}

TEST_CASE("memory_map::map_entry_to_page_frame")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t test_hpa = 0x0000000ABCDEF0000;

    epte_t expected_entry{0};
    epte::set_hpa(expected_entry, test_hpa);
    epte::read_access::enable(expected_entry);
    epte::write_access::enable(expected_entry);
    epte::memory_type::set(expected_entry, epte::memory_type::wb);
    epte::entry_type::enable(expected_entry);

    epte_t entry{0};
    mem_map->map_entry_to_page_frame(entry, test_hpa);
    CHECK(entry == expected_entry);
}

TEST_CASE("memory_map::gpa_to_pml4e")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    epte_t pml4e{0};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    allocate_mock_empty_pml4(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK(pml4e == 0);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK(epte::read_access::is_enabled(pml4e));
    CHECK(epte::write_access::is_enabled(pml4e));
    CHECK(epte::execute_access::is_disabled(pml4e));
    CHECK(epte::hpa(pml4e) == mock_pdpt_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::gpa_to_pdpte")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    epte_t pml4e{0};
    epte_t pdpte{0};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    allocate_mock_empty_pml4(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    CHECK_THROWS(mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e));
    free_mock_tables();

    allocate_mock_1g_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    CHECK(epte::read_access::is_enabled(pdpte));
    CHECK(epte::write_access::is_enabled(pdpte));
    CHECK(epte::execute_access::is_disabled(pdpte));
    CHECK(epte::entry_type::is_enabled(pdpte));
    CHECK(epte::hpa(pdpte) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    CHECK(epte::read_access::is_enabled(pdpte));
    CHECK(epte::write_access::is_enabled(pdpte));
    CHECK(epte::execute_access::is_disabled(pdpte));
    CHECK(epte::hpa(pdpte) == mock_pd_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::gpa_to_pde")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    epte_t pml4e{0};
    epte_t pdpte{0};
    epte_t pde{0};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    allocate_mock_2m_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    CHECK(epte::read_access::is_enabled(pde));
    CHECK(epte::write_access::is_enabled(pde));
    CHECK(epte::execute_access::is_disabled(pde));
    CHECK(epte::entry_type::is_enabled(pde));
    CHECK(epte::hpa(pde) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    CHECK(epte::read_access::is_enabled(pde));
    CHECK(epte::write_access::is_enabled(pde));
    CHECK(epte::execute_access::is_disabled(pde));
    CHECK(epte::hpa(pde) == mock_pt_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::gpa_to_pte")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    epte_t pml4e{0};
    epte_t pdpte{0};
    epte_t pde{0};
    epte_t pte{0};
    mem_map->m_pml4_hpa = mock_pml4_hpa;

    allocate_mock_4k_page(*mem_map);
    pml4e = mem_map->gpa_to_pml4e(g_mapped_gpa);
    pdpte = mem_map->gpa_to_pdpte(g_mapped_gpa, pml4e);
    pde = mem_map->gpa_to_pde(g_mapped_gpa, pdpte);
    pte = mem_map->gpa_to_pte(g_mapped_gpa, pde);
    CHECK(epte::read_access::is_enabled(pte));
    CHECK(epte::write_access::is_enabled(pte));
    CHECK(epte::execute_access::is_disabled(pte));
    CHECK(epte::entry_type::is_enabled(pte));
    CHECK(epte::hpa(pte) == mock_page_hpa);
    free_mock_tables();
}

// TEST_CASE("memory_map::hpa_to_gpa")
// {
//     MockRepository mocks;
//     auto mm = setup_mock_ept_memory_manager(mocks);
//     auto mem_map = new ept::memory_map();
//     mem_map->m_pml4_hpa = mock_pml4_hpa;
//
//     allocate_mock_empty_pml4(*mem_map);
//     mem_map->map(0xabcd0000, 0xabcd0000, pte::page_size_bytes);
//     CHECK(mem_map->hpa_to_gpa(0xabcd0000) == 0xabcd0000);
//     free_mock_tables();
//
//     allocate_mock_4k_page(*mem_map);
//     mem_map->map(0, 0xabcd0000, pte::page_size_bytes);
//     CHECK(mem_map->hpa_to_gpa(0) == 0xabcd0000);
//     free_mock_tables();
// }

TEST_CASE("memory_map::map_pdpte_to_page")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    epte_t result{0};

    allocate_mock_empty_pml4(*mem_map);
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pdpte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pdpte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::map_pde_to_page")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    epte_t result{0};

    allocate_mock_empty_pml4(*mem_map);
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pde_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pde_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::map_pte_to_page")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    mem_map->m_pml4_hpa = mock_pml4_hpa;
    epte_t result{0};

    allocate_mock_empty_pml4(*mem_map);
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_1g_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_2m_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();

    allocate_mock_4k_page(*mem_map);
    CHECK_THROWS(mem_map->map_pte_to_page(g_mapped_gpa, mock_page_hpa));
    result = mem_map->map_pte_to_page(g_unmapped_gpa, mock_page_hpa);
    CHECK(epte::read_access::is_enabled(result));
    CHECK(epte::write_access::is_enabled(result));
    CHECK(epte::execute_access::is_disabled(result));
    CHECK(epte::entry_type::is_enabled(result));
    CHECK(epte::memory_type::get(result) == epte::memory_type::wb);
    CHECK(epte::hpa(result) == mock_page_hpa);
    free_mock_tables();
}

TEST_CASE("memory_map::to_mdl")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    mem_map->map(0xf00d0000, 0, ept::pte::page_size_bytes);

    auto result = mem_map->to_mdl();
    CHECK(result.size() == 4);

    mem_map->map(0xbeef00000, 0, ept::pte::page_size_bytes);
    result = mem_map->to_mdl();
    CHECK(result.size() == 6);
    free_mock_tables();
}

}
}
}

#endif
