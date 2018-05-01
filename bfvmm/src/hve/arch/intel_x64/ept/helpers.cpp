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
#include "hve/arch/intel_x64/hve.h"
#include "hve/arch/intel_x64/ept/helpers.h"
#include "hve/arch/intel_x64/ept/memory_map.h"
#include "hve/arch/intel_x64/ept/intrinsics.h"

namespace vmcs = intel_x64::vmcs;
namespace eptp = intel_x64::vmcs::ept_pointer;

namespace eapis
{
namespace intel_x64
{
namespace ept
{

uintptr_t align_1g(uintptr_t addr)
{ return (addr & ~(ept::page_size_1g - 1U)); }

uintptr_t align_2m(uintptr_t addr)
{ return (addr & ~(ept::page_size_2m - 1U)); }

uintptr_t align_4k(uintptr_t addr)
{ return (addr & ~(ept::page_size_4k - 1U)); }

uint64_t
eptp(memory_map &map)
{
    auto val = 0ULL;
    auto pml4_hpa = map.hpa();

    val = eptp::memory_type::set(val, eptp::memory_type::write_back);
    val = eptp::page_walk_length_minus_one::set(val, max_page_walk_length - 1U);
    val = eptp::accessed_and_dirty_flags::disable(val);
    val = eptp::phys_addr::set(val, pml4_hpa);

    return val;
}

void
enable_ept(uint64_t eptp, gsl::not_null<eapis::intel_x64::hve *> hve)
{
    vmcs::ept_pointer::set(eptp);
    vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
    hve->enable_vpid();
}

void
disable_ept(void)
{ vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable(); }

//--------------------------------------------------------------------------
// 1GB pages
//--------------------------------------------------------------------------

void
map_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto &entry = mem_map.map(gpa, hpa, pdpte::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
map_n_contig_1g(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        map_1g(mem_map, gpa + (i * page_size_1g), hpa + (i * page_size_1g), mattr);
    }
}

void
map_range_1g(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_1g) + 1ULL;
    map_n_contig_1g(mem_map, gpa_s, hpa, n, mattr);
}

void
identity_map_1g(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_1g(mem_map, gpa, gpa, mattr); }

void
identity_map_n_contig_1g(memory_map &mem_map, gpa_t gpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_1g(mem_map, gpa + (i * page_size_1g), mattr);
    }
}

void
identity_map_range_1g(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_1g) + 1ULL;
    identity_map_n_contig_1g(mem_map, gpa_s, n, mattr);
}

//--------------------------------------------------------------------------
// 2MB pages
//--------------------------------------------------------------------------

void
map_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto &entry = mem_map.map(gpa, hpa, pde::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
map_n_contig_2m(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        map_2m(mem_map, gpa + (i * page_size_2m), hpa + (i * page_size_2m), mattr);
    }
}

void
map_range_2m(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_2m) + 1ULL;
    map_n_contig_2m(mem_map, gpa_s, hpa, n, mattr);
}

void
identity_map_2m(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_2m(mem_map, gpa, gpa, mattr); }

void
identity_map_n_contig_2m(memory_map &mem_map, gpa_t gpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_2m(mem_map, gpa + (i * page_size_2m), mattr);
    }
}

void
identity_map_range_2m(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_2m) + 1ULL;
    identity_map_n_contig_2m(mem_map, gpa_s, n, mattr);
}

//--------------------------------------------------------------------------
// 4KB pages
//--------------------------------------------------------------------------

void
map_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa, memory_attr_t mattr)
{
    auto &entry = mem_map.map(gpa, hpa, pte::page_size_bytes);
    epte::memory_attr::set(entry, mattr);
}

void
map_n_contig_4k(memory_map &mem_map, gpa_t gpa, hpa_t hpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        map_4k(mem_map, gpa + (i * page_size_4k), hpa + (i * page_size_4k), mattr);
    }
}

void
map_range_4k(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_4k) + 1ULL;
    map_n_contig_4k(mem_map, gpa_s, hpa, n, mattr);
}

void
identity_map_4k(memory_map &mem_map, gpa_t gpa, memory_attr_t mattr)
{ map_4k(mem_map, gpa, gpa, mattr); }

void
identity_map_n_contig_4k(memory_map &mem_map, gpa_t gpa, uint64_t n, memory_attr_t mattr)
{
    for (auto i = 0ULL; i < n; i++) {
        identity_map_4k(mem_map, gpa + (i * page_size_4k), mattr);
    }
}

void
identity_map_range_4k(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, memory_attr_t mattr)
{
    expects(gpa_s < gpa_e);

    auto n = ((gpa_e - gpa_s) / page_size_4k) + 1ULL;
    identity_map_n_contig_4k(mem_map, gpa_s, n, mattr);
}

void
identity_map_bestfit_lo(ept::memory_map &emm, uintptr_t gpa_s, uintptr_t gpa_e,
    memory_attr_t mattr)
{
    expects(gpa_s == align_1g(gpa_s));
    expects(gpa_s < align_4k(gpa_e));

    const auto end_1g = align_1g(gpa_e);
    const auto end_2m = align_2m(gpa_e);
    const auto end_4k = align_4k(gpa_e);

    auto i = gpa_s;

    for (; i < end_1g; i += ept::page_size_1g) {
        ept::identity_map_1g(emm, i, mattr);
    }

    for(; i < end_2m; i += ept::page_size_2m) {
        ept::identity_map_2m(emm, i, mattr);
    }

    for (; i <= end_4k; i += ept::page_size_4k) {
        ept::identity_map_4k(emm, i, mattr);
    }
}

void
identity_map_bestfit_hi(ept::memory_map &emm, uintptr_t gpa_s, uintptr_t gpa_e,
    memory_attr_t mattr)
{
    expects(align_4k(gpa_s) == gpa_s);
    expects(align_1g(gpa_e) == gpa_e);

    const auto end_4k = align_2m(gpa_s) + ept::page_size_2m;
    const auto end_2m = align_1g(gpa_s) + ept::page_size_1g;
    const auto end_1g = gpa_e;

    auto i = gpa_s;

    for (; i < end_4k; i += ept::page_size_4k) {
        ept::identity_map_4k(emm, i, mattr);
    }

    for (; i < end_2m; i += ept::page_size_2m) {
        ept::identity_map_2m(emm, i, mattr);
    }

    for (; i <= end_1g; i += ept::page_size_1g) {
        ept::identity_map_1g(emm, i, mattr);
    }
}

//--------------------------------------------------------------------------
// Unmapping
//--------------------------------------------------------------------------

void
unmap(memory_map &mem_map, gpa_t gpa)
{ mem_map.unmap(gpa); }

}
}
}
