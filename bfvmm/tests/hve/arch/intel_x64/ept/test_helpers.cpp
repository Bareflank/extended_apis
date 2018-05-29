//
// Bareflank Extended APIs
//
// Copyright (C) 2018 Assured Information Security, Inc.
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
#include <support/arch/intel_x64/test_support.h>
#include "ept_test_support.h"

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eptp = intel_x64::vmcs::ept_pointer;

namespace test_ept
{

//--------------------------------------------------------------------------
// Alignment
//--------------------------------------------------------------------------

TEST_CASE("ept::align_1g")
{
    auto addr = 0x1122334455667788U;
    CHECK(ept::align_1g(addr) == (addr & ~(ept::page_size_1g - 1U)));
}

TEST_CASE("ept::ept::align_2m")
{
    auto addr = 0x1122334455667788U;
    CHECK(ept::align_2m(addr) == (addr & ~(ept::page_size_2m - 1U)));
}

TEST_CASE("ept::ept::align_4k")
{
    auto addr = 0x1122334455667788U;
    CHECK(ept::align_4k(addr) == (addr & ~(ept::page_size_4k - 1U)));
}

//--------------------------------------------------------------------------
// EPT pointer
//--------------------------------------------------------------------------

TEST_CASE("ept::eptp")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    uint64_t expected{0};
    eptp::memory_type::set(expected, eptp::memory_type::write_back);
    eptp::page_walk_length_minus_one::set(expected, 3ULL);
    eptp::phys_addr::set(expected, mem_map->m_pml4_hpa);

    uint64_t eptp_val = ept::eptp(*mem_map);
    CHECK(eptp_val == expected);
}

//--------------------------------------------------------------------------
// 1GB pages
//--------------------------------------------------------------------------

TEST_CASE("ept::map_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_1g_hpa;
    ept::epte_t result_entry{0ULL};

    ept::map_1g(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_1g_hpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_1g(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_n_contig_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_1g;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_1g);
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_1g(*mem_map, gpa, hpa, page_count);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_n_contig_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_1g;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_1g(*mem_map, gpa, hpa, page_count, mattr);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_range_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_1g;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_1g);
    ept::epte_t result_entry{0ULL};

    ept::map_range_1g(*mem_map, gpa, end_gpa, hpa);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_range_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_1g;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_range_1g(*mem_map, gpa, end_gpa, hpa, mattr);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::wb_rw;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_1g(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_1g(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_1g(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_1g(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_n_contig_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_1g(*mem_map, gpa, page_count);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_n_contig_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_1g(*mem_map, gpa, page_count, mattr);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_range_1g")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_1g(*mem_map, gpa, end_gpa);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_range_1g with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_1g(*mem_map, gpa, end_gpa, mattr);
    CHECK_THROWS(ept::map_1g(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_1g(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_1g));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

//--------------------------------------------------------------------------
// 2MB pages
//--------------------------------------------------------------------------

TEST_CASE("ept::map_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_2m_hpa;
    ept::epte_t result_entry{0ULL};

    ept::map_2m(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_2m_hpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_2m(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_n_contig_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_2m;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_2m);
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_2m(*mem_map, gpa, hpa, page_count);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_n_contig_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_2m;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_2m(*mem_map, gpa, hpa, page_count, mattr);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_range_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_2m;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_2m);
    ept::epte_t result_entry{0ULL};

    ept::map_range_2m(*mem_map, gpa, end_gpa, hpa);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_range_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_2m;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_range_2m(*mem_map, gpa, end_gpa, hpa, mattr);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::wb_rw;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_2m(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_2m(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_2m(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_2m(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_n_contig_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_2m(*mem_map, gpa, page_count);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_n_contig_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_2m(*mem_map, gpa, page_count, mattr);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_range_2m")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_2m(*mem_map, gpa, end_gpa);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_range_2m with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_2m);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_2m(*mem_map, gpa, end_gpa, mattr);
    CHECK_THROWS(ept::map_2m(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_2m(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_2m));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

//--------------------------------------------------------------------------
// 4KB pages
//--------------------------------------------------------------------------

TEST_CASE("ept::map_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_4k_hpa;
    ept::epte_t result_entry{0ULL};

    ept::map_4k(*mem_map, gpa, hpa);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
}

TEST_CASE("ept::map_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = test_ept::mock_4k_hpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_4k(*mem_map, gpa, hpa, mtype);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa, mtype));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_n_contig_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_4k;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_4k);
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_4k(*mem_map, gpa, hpa, page_count);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_n_contig_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_4k;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_n_contig_4k(*mem_map, gpa, hpa, page_count, mattr);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::map_range_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_4k;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_4k);
    ept::epte_t result_entry{0ULL};

    ept::map_range_4k(*mem_map, gpa, end_gpa, hpa);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
}

TEST_CASE("ept::map_range_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t hpa = gpa + ept::page_size_4k;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t end_hpa = hpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::map_range_4k(*mem_map, gpa, end_gpa, hpa, mattr);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, hpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_hpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_hpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::wb_rw;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_4k(*mem_map, gpa);
    CHECK_THROWS(ept::identity_map_4k(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
}

TEST_CASE("ept::identity_map_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    ept::memory_attr_t mtype = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_4k(*mem_map, gpa, mtype);
    CHECK_THROWS(ept::identity_map_4k(*mem_map, gpa));
    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_n_contig_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_4k(*mem_map, gpa, page_count);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_n_contig_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_n_contig_4k(*mem_map, gpa, page_count, mattr);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_range_4k")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_4k(*mem_map, gpa, end_gpa);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
}

TEST_CASE("ept::identity_map_range_4k with attributes")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_4k);
    uintptr_t mattr = ept::epte::memory_attr::uc_eo;
    ept::epte_t result_entry{0ULL};

    ept::identity_map_range_4k(*mem_map, gpa, end_gpa, mattr);
    CHECK_THROWS(ept::map_4k(*mem_map, gpa, gpa));
    CHECK_THROWS(ept::map_4k(*mem_map, end_gpa, end_gpa));
    CHECK_THROWS(mem_map->gpa_to_epte(end_gpa + ept::page_size_4k));

    result_entry = mem_map->gpa_to_epte(gpa);
    CHECK(ept::epte::hpa(result_entry) == gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);

    result_entry = mem_map->gpa_to_epte(end_gpa);
    CHECK(ept::epte::hpa(result_entry) == end_gpa);
    CHECK(ept::epte::read_access::is_disabled(result_entry));
    CHECK(ept::epte::write_access::is_disabled(result_entry));
    CHECK(ept::epte::execute_access::is_enabled(result_entry));
    CHECK(ept::epte::memory_type::get(result_entry) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_bestfit_lo throws")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    CHECK_THROWS(ept::identity_map_bestfit_lo(*mem_map, 0x1000U, 0U));
    CHECK_THROWS(ept::identity_map_bestfit_lo(*mem_map, 0x100000U, 0U));
    CHECK_THROWS(ept::identity_map_bestfit_lo(*mem_map, 0x1000U, 0x1000U));
    CHECK_THROWS(ept::identity_map_bestfit_lo(*mem_map, 0x1000U, 0x100FU));
}

TEST_CASE("ept::identity_map_bestfit_lo 4K end page")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    uintptr_t gpa = test_ept::g_unmapped_gpa + ept::page_size_1g;
    uintptr_t start = gpa + ept::page_size_1g;
    uintptr_t end = start + ept::page_size_4k;

    ept::identity_map_bestfit_lo(*mem_map, start, end);

    auto entry_1g = mem_map->gpa_to_epte(start);
    auto entry_4k = mem_map->gpa_to_epte(end);

    CHECK(ept::epte::entry_type::is_enabled(entry_1g));
    CHECK(ept::epte::entry_type::is_enabled(entry_4k));
    CHECK(ept::epte::memory_type::get(entry_1g) == ept::epte::memory_type::wb);
    CHECK(ept::epte::memory_type::get(entry_4k) == ept::epte::memory_type::wb);
}

TEST_CASE("ept::identity_map_bestfit_lo mattr")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa;
    uintptr_t end_gpa = gpa + ((page_count - 1) * ept::page_size_1g);
    uintptr_t mattr = ept::epte::memory_attr::uc_pt;

    ept::identity_map_bestfit_lo(*mem_map, gpa, end_gpa - ept::page_size_4k, mattr);

    auto entry_1g = mem_map->gpa_to_epte(gpa);
    auto entry_2m = mem_map->gpa_to_epte(end_gpa - 512 * ept::page_size_2m);
    auto entry_4k = mem_map->gpa_to_epte(end_gpa - ept::page_size_4k);

    CHECK(ept::epte::entry_type::is_enabled(entry_1g));
    CHECK(ept::epte::entry_type::is_enabled(entry_2m));
    CHECK(ept::epte::entry_type::is_enabled(entry_4k));

    CHECK(ept::epte::memory_type::get(entry_1g) == ept::epte::memory_type::uc);
    CHECK(ept::epte::memory_type::get(entry_2m) == ept::epte::memory_type::uc);
    CHECK(ept::epte::memory_type::get(entry_4k) == ept::epte::memory_type::uc);
}

TEST_CASE("ept::identity_map_bestfit_hi throws")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();

    CHECK_THROWS(ept::identity_map_bestfit_hi(*mem_map, 0x1001U, 0U));
    CHECK_THROWS(ept::identity_map_bestfit_hi(*mem_map, 0x100000U, 0x2000U));
}

TEST_CASE("ept::identity_map_bestfit_hi 4K end page")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 10ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa + ept::page_size_4k;
    uintptr_t end_gpa = ept::align_1g(gpa + ((page_count - 1) * ept::page_size_1g));

    ept::identity_map_bestfit_hi(*mem_map, gpa, end_gpa);

    auto entry_4k = mem_map->gpa_to_epte(gpa);
    auto entry_2m = mem_map->gpa_to_epte(ept::align_2m(gpa + ept::page_size_2m));
    auto entry_1g = mem_map->gpa_to_epte(ept::align_1g(gpa + ept::page_size_1g));

    CHECK(ept::epte::entry_type::is_enabled(entry_4k));
    CHECK(ept::epte::entry_type::is_enabled(entry_2m));
    CHECK(ept::epte::entry_type::is_enabled(entry_1g));
}

TEST_CASE("ept::identity_map_bestfit_hi mattr")
{
    MockRepository mocks;
    auto mock_ept = std::make_unique<ept_test_support>(mocks);
    auto mem_map = std::make_unique<ept::memory_map>();
    auto page_count = 2ULL;
    uintptr_t gpa = test_ept::g_unmapped_gpa + ept::page_size_1g - ept::page_size_4k;
    uintptr_t end_gpa = test_ept::g_unmapped_gpa + ept::page_size_1g;
    uintptr_t mattr = ept::epte::memory_attr::wc_eo;

    ept::identity_map_bestfit_hi(*mem_map, gpa, end_gpa);

    auto entry_4k = mem_map->gpa_to_epte(gpa);
    auto entry_1g = mem_map->gpa_to_epte(gpa + ept::page_size_4k);

    CHECK(ept::epte::entry_type::is_enabled(entry_4k));
    CHECK(ept::epte::entry_type::is_enabled(entry_1g));
}

}

#endif
