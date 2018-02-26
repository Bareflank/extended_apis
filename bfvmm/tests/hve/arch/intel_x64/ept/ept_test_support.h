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
#include <hippomocks.h>

#include "hve/arch/intel_x64/ept.h"
#include <bfvmm/memory_manager/memory_manager.h>

namespace eapis
{
namespace intel_x64
{
namespace ept
{

constexpr const uintptr_t mock_pml4_hpa = 0x000ABCD000000000ULL;
constexpr const uintptr_t mock_pdpt_hpa = 0x0000000ABCD00000ULL;
constexpr const uintptr_t mock_pd_hpa = 0x0000000123400000ULL;
constexpr const uintptr_t mock_pt_hpa = 0x0000000DCBA00000ULL;
constexpr const uintptr_t mock_page_hpa = 0x000000000F00D000ULL;

constexpr const uint64_t mock_pml4e_offset = 0xFF8;
constexpr const uint64_t mock_pdpte_offset = 0xFF8;
constexpr const uint64_t mock_pde_offset = 0xFF8;
constexpr const uint64_t mock_pte_offset = 0xFF8;
constexpr const uint64_t mock_page_offset = 0xA55A;

constexpr const uintptr_t mock_1g_hpa = 0xFFFFC0000000ULL;
constexpr const uintptr_t mock_2m_hpa = 0xFFFFFFE00000ULL;
constexpr const uintptr_t mock_4k_hpa = 0xFFFFFFFFF000ULL;

// The following gpa is mapped into all mocked memory maps
constexpr const uintptr_t g_mapped_gpa = 0x0000FFFFFFFFF000ULL;

// The following gpa is not mapped by any entries in any mocked memory maps
constexpr const uintptr_t g_unmapped_gpa = 0x0000000000000000ULL;

std::map<void *, uintptr_t> g_mock_mem;

static volatile uintptr_t g_next_phys_addr = 0x00000000F00D0000;

uintptr_t
mock_virtptr_to_physint(void * gva)
{
    if (g_mock_mem.count(gva)) {
        return g_mock_mem.at(gva);
    }

    g_next_phys_addr += 0x1000;
    g_mock_mem[gva] = g_next_phys_addr;
    return g_next_phys_addr;
}

void *
mock_virtptr_to_physptr(void * gva)
{
    return reinterpret_cast<void *>(mock_virtptr_to_physint(gva));
}

uintptr_t
mock_virtint_to_physint(uintptr_t gva)
{
    return mock_virtptr_to_physint(reinterpret_cast<void *>(gva));
}

void *
mock_virtint_to_physptr(uintptr_t gva)
{
    return reinterpret_cast<void *>(mock_virtint_to_physint(gva));
}

void *
mock_physint_to_virtptr(uintptr_t gpa)
{
    for (auto const& x : g_mock_mem) {
        if (x.second == gpa) {
            return x.first
        };
    }
    std::stringstream msg;
    msg << "invalid test guest physical address: " << std::hex << "0x" << gpa;
    throw std::logic_error(msg.str().c_str());
}

void *
mock_physptr_to_virtptr(void * gpa)
{
    return mock_physint_to_virtptr(reinterpret_cast<uintptr_t>(gpa));
}

uintptr_t
mock_physint_to_virtint(uintptr_t gpa)
{
    return reinterpret_cast<uintptr_t>(mock_physint_to_virtptr(gpa));
}

uintptr_t
mock_physptr_to_virtint(void * gpa)
{
    return reinterpret_cast<uintptr_t>(mock_physptr_to_virtptr(gpa));
}

auto
setup_mock_ept_memory_manager(MockRepository &mocks)
{
    auto mm = mocks.Mock<bfvmm::memory_manager>();
    mocks.OnCallFunc(bfvmm::memory_manager::instance).Return(mm);

    mocks.OnCall(mm, bfvmm::memory_manager::virtptr_to_physint).Do([&](auto gva) { return mock_virtptr_to_physint(gva); });
    mocks.OnCall(mm, bfvmm::memory_manager::virtint_to_physint).Do([&](auto gva) { return mock_virtint_to_physint(gva); });
    mocks.OnCall(mm, bfvmm::memory_manager::virtptr_to_physptr).Do([&](auto gva) { return mock_virtptr_to_physptr(gva); });
    mocks.OnCall(mm, bfvmm::memory_manager::virtint_to_physptr).Do([&](auto gva) { return mock_virtint_to_physptr(gva); });
    mocks.OnCall(mm, bfvmm::memory_manager::physint_to_virtptr).Do([&](auto gpa) { return mock_physint_to_virtptr(gpa); });
    mocks.OnCall(mm, bfvmm::memory_manager::physint_to_virtint).Do([&](auto gpa) { return mock_physint_to_virtint(gpa); });
    mocks.OnCall(mm, bfvmm::memory_manager::physptr_to_virtptr).Do([&](auto gpa) { return mock_physptr_to_virtptr(gpa); });
    mocks.OnCall(mm, bfvmm::memory_manager::physptr_to_virtint).Do([&](auto gpa) { return mock_physptr_to_virtint(gpa); });
    return mm;
}

void
allocate_mock_empty_pml4(ept::memory_map & map)
{
    void * pml4 = operator new(ept::page_table::size_bytes);
    map.m_pml4_hva = reinterpret_cast<uintptr_t>(pml4);
    memset(pml4, 0, ept::page_table::size_bytes);
    g_mock_mem[pml4] = mock_pml4_hpa;
}

void
allocate_mock_1g_page(ept::memory_map & map)
{
    void * pml4 = operator new(ept::page_table::size_bytes);
    void * pdpt = operator new(ept::page_table::size_bytes);
    void * page = operator new(ept::pte::page_size_bytes);
    memset(pml4, 0xFF, ept::page_table::size_bytes);
    memset(pdpt, 0xFF, ept::page_table::size_bytes);
    memset(page, 0xFF, ept::pte::page_size_bytes);

    // Setup mock page tables with one empty entry and one 1G page frame
    map.m_pml4_hva = reinterpret_cast<uintptr_t>(pml4);
    epte_t * pml4e = static_cast<epte_t *>(pml4);
    epte::clear(*pml4e);
    pml4e += (ept::page_table::num_entries - 1);
    epte::clear(*pml4e);
    epte::read_access::enable(*pml4e);
    epte::write_access::enable(*pml4e);
    epte::set_hpa(*pml4e, mock_pdpt_hpa & epte::phys_addr_bits::mask);

    epte_t * pdpte = static_cast<epte_t *>(pdpt);
    epte::clear(*pdpte);
    pdpte += (ept::page_table::num_entries - 1);
    epte::clear(*pdpte);
    epte::read_access::enable(*pdpte);
    epte::write_access::enable(*pdpte);
    epte::entry_type::enable(*pdpte);
    epte::set_hpa(*pdpte, mock_page_hpa);

    // Setup the mock memory manager's virt->phys mappings for the
    // page table entries allocated above
    g_mock_mem[pml4] = mock_pml4_hpa;
    g_mock_mem[pdpt] = mock_pdpt_hpa;
    g_mock_mem[page] = mock_page_hpa;
}

void
allocate_mock_2m_page(ept::memory_map & map)
{
    void * pml4 = operator new(ept::page_table::size_bytes);
    void * pdpt = operator new(ept::page_table::size_bytes);
    void * pd = operator new(ept::page_table::size_bytes);
    void * page = operator new(ept::pte::page_size_bytes);
    memset(pml4, 0xFF, ept::page_table::size_bytes);
    memset(pdpt, 0xFF, ept::page_table::size_bytes);
    memset(pd, 0xFF, ept::page_table::size_bytes);
    memset(page, 0xFF, ept::pte::page_size_bytes);

    // Setup mock page tables with one empty entry and one 2MB page frame
    map.m_pml4_hva = reinterpret_cast<uintptr_t>(pml4);
    epte_t * pml4e = static_cast<epte_t *>(pml4);
    epte::clear(*pml4e);
    pml4e += (ept::page_table::num_entries - 1);
    epte::clear(*pml4e);
    epte::read_access::enable(*pml4e);
    epte::write_access::enable(*pml4e);
    epte::set_hpa(*pml4e, mock_pdpt_hpa & epte::phys_addr_bits::mask);

    epte_t * pdpte = static_cast<epte_t *>(pdpt);
    epte::clear(*pdpte);
    pdpte += (ept::page_table::num_entries - 1);
    epte::clear(*pdpte);
    epte::read_access::enable(*pdpte);
    epte::write_access::enable(*pdpte);
    epte::set_hpa(*pdpte, mock_pd_hpa & epte::phys_addr_bits::mask);

    epte_t * pde = static_cast<epte_t *>(pd);
    epte::clear(*pde);
    pde += (ept::page_table::num_entries - 1);
    epte::clear(*pde);
    epte::read_access::enable(*pde);
    epte::write_access::enable(*pde);
    epte::entry_type::enable(*pde);
    epte::set_hpa(*pde, mock_page_hpa);

    // Setup the mock memory manager's virt->phys mappings for the
    // page table entries allocated above
    g_mock_mem[pml4] = mock_pml4_hpa;
    g_mock_mem[pdpt] = mock_pdpt_hpa;
    g_mock_mem[pd] = mock_pd_hpa;
    g_mock_mem[page] = mock_page_hpa;
}

void
allocate_mock_4k_page(ept::memory_map & map)
{
    void * pml4 = operator new(ept::page_table::size_bytes);
    void * pdpt = operator new(ept::page_table::size_bytes);
    void * pd = operator new(ept::page_table::size_bytes);
    void * pt = operator new(ept::page_table::size_bytes);
    void * page = operator new(ept::pte::page_size_bytes);
    memset(pml4, 0xFF, ept::page_table::size_bytes);
    memset(pdpt, 0xFF, ept::page_table::size_bytes);
    memset(pd, 0xFF, ept::page_table::size_bytes);
    memset(pt, 0xFF, ept::page_table::size_bytes);
    memset(page, 0xFF, ept::pte::page_size_bytes);

    // Setup mock page tables with one empty entry and one 4KB page frame
    map.m_pml4_hva = reinterpret_cast<uintptr_t>(pml4);
    epte_t * pml4e = static_cast<epte_t *>(pml4);
    epte::clear(*pml4e);
    pml4e += (ept::page_table::num_entries - 1);
    epte::clear(*pml4e);
    epte::read_access::enable(*pml4e);
    epte::write_access::enable(*pml4e);
    epte::set_hpa(*pml4e, mock_pdpt_hpa & epte::phys_addr_bits::mask);

    epte_t * pdpte = static_cast<epte_t *>(pdpt);
    epte::clear(*pdpte);
    pdpte += (ept::page_table::num_entries - 1);
    epte::clear(*pdpte);
    epte::read_access::enable(*pdpte);
    epte::write_access::enable(*pdpte);
    epte::set_hpa(*pdpte, mock_pd_hpa & epte::phys_addr_bits::mask);

    epte_t * pde = static_cast<epte_t *>(pd);
    epte::clear(*pde);
    pde += (ept::page_table::num_entries - 1);
    epte::clear(*pde);
    epte::read_access::enable(*pde);
    epte::write_access::enable(*pde);
    epte::set_hpa(*pde, mock_pt_hpa & epte::phys_addr_bits::mask);

    epte_t * pte = static_cast<epte_t *>(pt);
    epte::clear(*pte);
    pte += (ept::page_table::num_entries - 1);
    epte::clear(*pte);
    epte::read_access::enable(*pte);
    epte::write_access::enable(*pte);
    epte::entry_type::enable(*pte);
    epte::set_hpa(*pte, mock_page_hpa);

    // Setup the mock memory manager's virt->phys mappings for the
    // page table entries allocated above
    g_mock_mem[pml4] = mock_pml4_hpa;
    g_mock_mem[pdpt] = mock_pdpt_hpa;
    g_mock_mem[pd] = mock_pd_hpa;
    g_mock_mem[pt] = mock_pt_hpa;
    g_mock_mem[page] = mock_page_hpa;
}

void
free_mock_tables()
{
    for (auto const& item : g_mock_mem) {
        operator delete(item.first);
    }
    g_mock_mem.clear();
    g_next_phys_addr = 0xF00D0000;
}

}
}
}
