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

#include <catch/catch.hpp>
#include <hve/arch/intel_x64/ept/intrinsics.h>

namespace eapis
{
namespace intel_x64
{
namespace ept
{

namespace epte
{

TEST_CASE("epte: read_access")
{
    epte_t entry = 0ULL;
    auto mask = 0x1ULL;
    auto mask_invert = ~mask;

    CHECK(!read_access::is_enabled(entry));
    CHECK(read_access::is_disabled(entry));

    entry = mask_invert;
    CHECK(!read_access::is_enabled(entry));
    CHECK(read_access::is_disabled(entry));

    entry = mask;
    CHECK(read_access::is_enabled(entry));
    CHECK(!read_access::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(read_access::is_enabled(entry));
    CHECK(!read_access::is_disabled(entry));

    entry = 0ULL;
    read_access::enable(entry);
    CHECK(entry == mask);
    read_access::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    read_access::disable(entry);
    CHECK(entry == mask_invert);
    read_access::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: execute_access")
{
    epte_t entry = 0ULL;
    auto mask = 0x4ULL;
    auto mask_invert = ~mask;

    CHECK(!execute_access::is_enabled(entry));
    CHECK(execute_access::is_disabled(entry));

    entry = mask_invert;
    CHECK(!execute_access::is_enabled(entry));
    CHECK(execute_access::is_disabled(entry));

    entry = mask;
    CHECK(execute_access::is_enabled(entry));
    CHECK(!execute_access::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(execute_access::is_enabled(entry));
    CHECK(!execute_access::is_disabled(entry));

    entry = 0ULL;
    execute_access::enable(entry);
    CHECK(entry == mask);
    execute_access::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    execute_access::disable(entry);
    CHECK(entry == mask_invert);
    execute_access::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: memory_type")
{
    epte_t entry = 0ULL;
    epte_t val = 0ULL;
    auto mask = 0x38ULL;
    auto from = 3ULL;
    auto mask_invert = ~mask;

    val = memory_type::get(entry);
    CHECK(!val);

    entry = mask;
    val = memory_type::get(entry);
    CHECK(val == (mask >> from));

    entry = mask_invert;
    val = memory_type::get(entry);
    CHECK(val == 0ULL);

    entry = 0ULL;
    memory_type::set(entry, 0xffffffffffffffffULL);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    memory_type::set(entry, 0ULL);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: ignore_pat")
{
    epte_t entry = 0ULL;
    auto mask = 0x40ULL;
    auto mask_invert = ~mask;

    CHECK(!ignore_pat::is_enabled(entry));
    CHECK(ignore_pat::is_disabled(entry));

    entry = mask_invert;
    CHECK(!ignore_pat::is_enabled(entry));
    CHECK(ignore_pat::is_disabled(entry));

    entry = mask;
    CHECK(ignore_pat::is_enabled(entry));
    CHECK(!ignore_pat::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(ignore_pat::is_enabled(entry));
    CHECK(!ignore_pat::is_disabled(entry));

    entry = 0ULL;
    ignore_pat::enable(entry);
    CHECK(entry == mask);
    ignore_pat::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    ignore_pat::disable(entry);
    CHECK(entry == mask_invert);
    ignore_pat::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: entry_type")
{
    epte_t entry = 0ULL;
    auto mask = 0x80ULL;
    auto mask_invert = ~mask;

    CHECK(!entry_type::is_enabled(entry));
    CHECK(entry_type::is_disabled(entry));

    entry = mask_invert;
    CHECK(!entry_type::is_enabled(entry));
    CHECK(entry_type::is_disabled(entry));

    entry = mask;
    CHECK(entry_type::is_enabled(entry));
    CHECK(!entry_type::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(entry_type::is_enabled(entry));
    CHECK(!entry_type::is_disabled(entry));

    entry = 0ULL;
    entry_type::enable(entry);
    CHECK(entry == mask);
    entry_type::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    entry_type::disable(entry);
    CHECK(entry == mask_invert);
    entry_type::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: accessed_flag")
{
    epte_t entry = 0ULL;
    auto mask = 0x100ULL;
    auto mask_invert = ~mask;

    CHECK(!accessed_flag::is_enabled(entry));
    CHECK(accessed_flag::is_disabled(entry));

    entry = mask_invert;
    CHECK(!accessed_flag::is_enabled(entry));
    CHECK(accessed_flag::is_disabled(entry));

    entry = mask;
    CHECK(accessed_flag::is_enabled(entry));
    CHECK(!accessed_flag::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(accessed_flag::is_enabled(entry));
    CHECK(!accessed_flag::is_disabled(entry));

    entry = 0ULL;
    accessed_flag::enable(entry);
    CHECK(entry == mask);
    accessed_flag::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    accessed_flag::disable(entry);
    CHECK(entry == mask_invert);
    accessed_flag::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: dirty")
{
    epte_t entry = 0ULL;
    auto mask = 0x200ULL;
    auto mask_invert = ~mask;

    CHECK(!dirty::is_enabled(entry));
    CHECK(dirty::is_disabled(entry));

    entry = mask_invert;
    CHECK(!dirty::is_enabled(entry));
    CHECK(dirty::is_disabled(entry));

    entry = mask;
    CHECK(dirty::is_enabled(entry));
    CHECK(!dirty::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(dirty::is_enabled(entry));
    CHECK(!dirty::is_disabled(entry));

    entry = 0ULL;
    dirty::enable(entry);
    CHECK(entry == mask);
    dirty::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    dirty::disable(entry);
    CHECK(entry == mask_invert);
    dirty::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: execute_access_user")
{
    epte_t entry = 0ULL;
    auto mask = 0x400ULL;
    auto mask_invert = ~mask;

    CHECK(!execute_access_user::is_enabled(entry));
    CHECK(execute_access_user::is_disabled(entry));

    entry = mask_invert;
    CHECK(!execute_access_user::is_enabled(entry));
    CHECK(execute_access_user::is_disabled(entry));

    entry = mask;
    CHECK(execute_access_user::is_enabled(entry));
    CHECK(!execute_access_user::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(execute_access_user::is_enabled(entry));
    CHECK(!execute_access_user::is_disabled(entry));

    entry = 0ULL;
    execute_access_user::enable(entry);
    CHECK(entry == mask);
    execute_access_user::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    execute_access_user::disable(entry);
    CHECK(entry == mask_invert);
    execute_access_user::disable(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: phys_addr_bits")
{
    epte_t entry = 0ULL;
    epte_t val = 0ULL;
    auto mask = 0x0000fffffffff000ULL;
    auto from = 12ULL;
    auto mask_invert = ~mask;

    val = phys_addr_bits::get(entry);
    CHECK(val == 0ULL);

    entry = mask;
    val = phys_addr_bits::get(entry);
    CHECK(val == (mask >> from));

    entry = mask_invert;
    val = phys_addr_bits::get(entry);
    CHECK(val == 0ULL);

    entry = 0ULL;
    phys_addr_bits::set(entry, 0xffffffffffffffffULL);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    phys_addr_bits::set(entry, 0ULL);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: suppress_ve")
{
    epte_t entry = 0ULL;
    auto mask = 0x8000000000000000ULL;
    auto mask_invert = ~mask;

    CHECK(!suppress_ve::is_enabled(entry));
    CHECK(suppress_ve::is_disabled(entry));

    entry = mask_invert;
    CHECK(!suppress_ve::is_enabled(entry));
    CHECK(suppress_ve::is_disabled(entry));

    entry = mask;
    CHECK(suppress_ve::is_enabled(entry));
    CHECK(!suppress_ve::is_disabled(entry));

    entry = 0xffffffffffffffffULL;
    CHECK(suppress_ve::is_enabled(entry));
    CHECK(!suppress_ve::is_disabled(entry));

    entry = 0ULL;
    suppress_ve::enable(entry);
    CHECK(entry == mask);
    suppress_ve::enable(entry);
    CHECK(entry == mask);

    entry = 0xffffffffffffffffULL;
    suppress_ve::disable(entry);
    CHECK(entry == mask_invert);
    suppress_ve::disable(entry);
}

TEST_CASE("epte: memory_attr")
{
    epte_t entry = 0x3fULL;
    CHECK(epte::memory_attr::get(entry) == 0x3fULL);
    entry = 0xffffffffffffffffULL;
    CHECK(epte::memory_attr::get(entry) == 0x3fULL);
    entry = 0ULL;
    CHECK(!epte::memory_attr::get(entry));
    entry = 1ULL;
    CHECK(epte::memory_attr::get(entry));
    entry = 5ULL;
    CHECK(epte::memory_attr::get(entry) == 5ULL);

    entry = 0ULL;
    epte::memory_attr::set(entry, 0x3fULL);
    CHECK(entry == 0x3fULL);
    entry = 0ULL;
    epte::memory_attr::set(entry, 5ULL);
    CHECK(entry == 5ULL);
    entry = 0xffffffffffffffffULL;
    epte::memory_attr::set(entry, 0ULL);
    CHECK(entry == 0xffffffffffffffc0ULL);
}

TEST_CASE("epte: trap_on_access")
{
    epte_t entry = 0ULL;
    auto mask = 0x7ULL;
    auto mask_invert = ~mask;

    trap_on_access(entry);
    CHECK(entry == 0ULL);

    entry = mask;
    trap_on_access(entry);
    CHECK(entry == 0ULL);

    entry = 0xffffffffffffffffULL;
    trap_on_access(entry);
    CHECK(entry == mask_invert);
}

TEST_CASE("epte: pass_through_access")
{
    epte_t entry = 0ULL;
    auto mask = 0x7ULL;
    auto mask_invert = ~mask;

    pass_through_access(entry);
    CHECK(entry == mask);
    pass_through_access(entry);
    CHECK(entry == mask);

    entry = mask_invert;
    pass_through_access(entry);
    CHECK(entry == 0xffffffffffffffffULL);
}

TEST_CASE("epte: clear")
{
    epte_t entry = 0xffffffffffffffffULL;

    clear(entry);
    CHECK(entry == 0ULL);
    clear(entry);
    CHECK(entry == 0ULL);
}

TEST_CASE("epte: is_present")
{
    epte_t entry = 0xffffffffffffffffULL;
    CHECK(epte::is_present(entry));

    entry = 1ULL;
    CHECK(epte::is_present(entry));
    entry = 2ULL;
    CHECK(epte::is_present(entry));
    entry = 4ULL;
    CHECK(epte::is_present(entry));
    entry = 0x400ULL;
    CHECK(epte::is_present(entry));

    entry = 0ULL;
    CHECK(!epte::is_present(entry));
    entry = 0x10ULL;
    CHECK(!epte::is_present(entry));
}

TEST_CASE("epte: is_leaf_entry")
{
    epte_t entry = 0xffffffffffffffffULL;
    CHECK(epte::is_leaf_entry(entry));
    entry = 0x80ULL;
    CHECK(epte::is_leaf_entry(entry));

    entry = 0ULL;
    CHECK(!epte::is_leaf_entry(entry));
    entry = 0x40ULL;
    CHECK(!epte::is_leaf_entry(entry));
    entry = 0x100ULL;
    CHECK(!epte::is_leaf_entry(entry));
}

TEST_CASE("epte: hpa")
{
    epte_t entry = 0ULL;
    uintptr_t result = 0ULL;

    result = hpa(entry);
    CHECK(result == 0ULL);

    phys_addr_bits::set(entry, 0xffffffffffffffffULL);
    CHECK(hpa(entry) == 0xfffffffff000ULL);

    entry = 0ULL;
    phys_addr_bits::set(entry, 0xf00dbeefULL);
    CHECK(hpa(entry) == 0xf00dbeef000ULL);
}

TEST_CASE("epte: set_hpa")
{
    epte_t entry = 0ULL;
    uintptr_t result = 0ULL;

    set_hpa(entry, 0ULL);
    CHECK(entry == 0ULL);

    set_hpa(entry, 0xffffffffffffULL);
    result = phys_addr_bits::get(entry);
    CHECK(result == 0xfffffffffULL);
}

} // end namespace epte

TEST_CASE("gpa")
{
    gpa_t gpa = 0ULL;
    CHECK(gpa::pml4_index::get_offset(gpa) == 0ULL);
    CHECK(gpa::pdpt_index::get_offset(gpa) == 0ULL);
    CHECK(gpa::pdpt_page_offset::get(gpa) == 0ULL);
    CHECK(gpa::pd_index::get_offset(gpa) == 0ULL);
    CHECK(gpa::pd_page_offset::get(gpa) == 0ULL);
    CHECK(gpa::pt_page_offset::get(gpa) == 0ULL);

    gpa = 0xffffffffffffffffULL;
    CHECK(gpa::pml4_index::get_offset(gpa) == gpa::pml4_index::mask >> gpa::pml4_index::shift);
    CHECK(gpa::pdpt_index::get_offset(gpa) == gpa::pdpt_index::mask >> gpa::pdpt_index::shift);
    CHECK(gpa::pdpt_page_offset::get(gpa) == gpa::pdpt_page_offset::mask >> gpa::pdpt_page_offset::from);
    CHECK(gpa::pd_index::get_offset(gpa) == gpa::pd_index::mask >> gpa::pd_index::shift);
    CHECK(gpa::pd_page_offset::get(gpa) == gpa::pd_page_offset::mask >> gpa::pd_page_offset::from);
    CHECK(gpa::pt_page_offset::get(gpa) == gpa::pt_page_offset::mask >> gpa::pt_page_offset::from);
}

TEST_CASE("pml4e")
{
    epte_t pml4e = 0ULL;
    CHECK(pml4e::table_address::is_aligned(pml4e));
    pml4e = 0xffffffe00000ULL;
    CHECK(pml4e::table_address::is_aligned(pml4e));
    pml4e = 0x00f00de00000ULL;
    CHECK(pml4e::table_address::is_aligned(pml4e));

    pml4e = 0xffffffffffffffffULL;
    CHECK(!pml4e::table_address::is_aligned(pml4e));
    pml4e = 0x00f00df00000ULL;
    CHECK(!pml4e::table_address::is_aligned(pml4e));
    pml4e = 1ULL;
    CHECK(!pml4e::table_address::is_aligned(pml4e));
    pml4e = 2ULL;
    CHECK(!pml4e::table_address::is_aligned(pml4e));
    pml4e = 3ULL;
    CHECK(!pml4e::table_address::is_aligned(pml4e));
}

TEST_CASE("pdpte")
{
    epte_t pdpte = 0ULL;
    CHECK(pdpte::table_address::is_aligned(pdpte));
    pdpte = 0xfffffffff000ULL;
    CHECK(pdpte::table_address::is_aligned(pdpte));
    pdpte = 0x000f00dff000ULL;
    CHECK(pdpte::table_address::is_aligned(pdpte));

    pdpte = 0xffffffffffffffffULL;
    CHECK(!pdpte::table_address::is_aligned(pdpte));
    pdpte = 0x000f00dff700ULL;
    CHECK(!pdpte::table_address::is_aligned(pdpte));
    pdpte = 1ULL;
    CHECK(!pdpte::table_address::is_aligned(pdpte));
    pdpte = 2ULL;
    CHECK(!pdpte::table_address::is_aligned(pdpte));
    pdpte = 3ULL;
    CHECK(!pdpte::table_address::is_aligned(pdpte));

    pdpte = 0ULL;
    CHECK(pdpte::page_address::is_aligned(pdpte));
    pdpte = 0xffffc0000000ULL;
    CHECK(pdpte::page_address::is_aligned(pdpte));
    pdpte = 0xf00dc0000000ULL;
    CHECK(pdpte::page_address::is_aligned(pdpte));

    pdpte = 0xffffe0000000ULL;
    CHECK(!pdpte::page_address::is_aligned(pdpte));
    pdpte = 0xffffffffffffULL;
    CHECK(!pdpte::page_address::is_aligned(pdpte));
    pdpte = 1ULL;
    CHECK(!pdpte::page_address::is_aligned(pdpte));
    pdpte = 2ULL;
    CHECK(!pdpte::page_address::is_aligned(pdpte));
    pdpte = 3ULL;
    CHECK(!pdpte::page_address::is_aligned(pdpte));

    pdpte = 0x000f00dff000ULL;
    CHECK(pdpte::page_address::get_effective_address(pdpte, 0xa5ULL) == 0x000f00dff0a5ULL);
}

TEST_CASE("pde")
{
    epte_t pde = 0ULL;
    CHECK(pde::table_address::is_aligned(pde));
    pde = 0xfffffffff000ULL;
    CHECK(pde::table_address::is_aligned(pde));
    pde = 0x000f00dff000ULL;
    CHECK(pde::table_address::is_aligned(pde));

    pde = 0xffffffffffffffffULL;
    CHECK(!pde::table_address::is_aligned(pde));
    pde = 0x000f00dff700ULL;
    CHECK(!pde::table_address::is_aligned(pde));
    pde = 1ULL;
    CHECK(!pde::table_address::is_aligned(pde));
    pde = 2ULL;
    CHECK(!pde::table_address::is_aligned(pde));
    pde = 3ULL;
    CHECK(!pde::table_address::is_aligned(pde));

    pde = 0ULL;
    CHECK(pde::page_address::is_aligned(pde));
    pde = 0xffffffe00000ULL;
    CHECK(pde::page_address::is_aligned(pde));
    pde = 0x0f00dfe00000ULL;
    CHECK(pde::page_address::is_aligned(pde));

    pde = 0xfffffff00000ULL;
    CHECK(!pde::page_address::is_aligned(pde));
    pde = 0xffffffffffffULL;
    CHECK(!pde::page_address::is_aligned(pde));
    pde = 1ULL;
    CHECK(!pde::page_address::is_aligned(pde));
    pde = 2ULL;
    CHECK(!pde::page_address::is_aligned(pde));
    pde = 3ULL;
    CHECK(!pde::page_address::is_aligned(pde));

    pde = 0x0f00dfe00000ULL;
    CHECK(pde::page_address::get_effective_address(pde, 0xa5ULL) == 0x0f00dfe000a5ULL);
}

TEST_CASE("pte")
{
    epte_t pte = 0ULL;
    CHECK(pte::page_address::is_aligned(pte));
    pte = 0xfffffffff000ULL;
    CHECK(pte::page_address::is_aligned(pte));
    pte = 0x000f00dff000ULL;
    CHECK(pte::page_address::is_aligned(pte));

    pte = 0xfffffffff700ULL;
    CHECK(!pte::page_address::is_aligned(pte));
    pte = 0xffffffffffffULL;
    CHECK(!pte::page_address::is_aligned(pte));
    pte = 1ULL;
    CHECK(!pte::page_address::is_aligned(pte));
    pte = 2ULL;
    CHECK(!pte::page_address::is_aligned(pte));
    pte = 3ULL;
    CHECK(!pte::page_address::is_aligned(pte));

    pte = 0x000f00dff000ULL;
    CHECK(pte::page_address::get_effective_address(pte, 0xa5ULL) == 0x000f00dff0a5ULL);
}

}
}
}
