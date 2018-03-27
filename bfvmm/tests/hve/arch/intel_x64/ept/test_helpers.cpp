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
#include "ept_test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eptp = intel_x64::vmcs::ept_pointer;

namespace eapis
{
namespace intel_x64
{
namespace ept
{

TEST_CASE("ept::eptp")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();

    uint64_t expected{0};
    expected = eptp::memory_type::set(expected, eptp::memory_type::write_back);
    expected = eptp::page_walk_length_minus_one::set(expected, 3);
    expected = eptp::phys_addr::set(expected, mem_map->m_pml4_hpa);

    uint64_t eptp_val = ept::eptp(*mem_map);
    CHECK(eptp_val == expected);
}

TEST_CASE("ept::map_1g")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_1g_hpa;
    epte_t result_entry{0};

    ept::map_1g(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_1g with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_1g_hpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::map_1g(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::identity_map_1g")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_1g(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_1g(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_1g with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_1g(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_1g(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::map_2m")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_2m_hpa;
    epte_t result_entry{0};

    ept::map_2m(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_2m with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_2m_hpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::map_2m(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::identity_map_2m")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_2m(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_2m(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_2m with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_2m(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_2m(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::map_4k")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_4k_hpa;
    epte_t result_entry{0};

    ept::map_4k(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_4k with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    uintptr_t hpa = mock_4k_hpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::map_4k(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::identity_map_4k")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_4k(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_4k(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_4k with attributes")
{
    MockRepository mocks;
    auto mm = setup_mock_ept_memory_manager(mocks);
    auto mem_map = new ept::memory_map();
    uintptr_t gpa = g_unmapped_gpa;
    ept::memory_attr_t mtype = epte::memory_attr::wb_rw;
    epte_t result_entry{0};

    ept::identity_map_4k(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_4k(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(epte::hpa(result_entry) == gpa);
}

}
}
}

#endif
