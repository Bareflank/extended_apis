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
#include "hve/arch/intel_x64/phys_mtrr.h"

namespace vmcs = intel_x64::vmcs;
namespace eptp = intel_x64::vmcs::ept_pointer;

namespace eapis
{
namespace intel_x64
{
namespace ept
{

static auto g_mtrrs = std::make_unique<::eapis::intel_x64::phys_mtrr>();

uintptr_t align_1g(uintptr_t addr)
{ return (addr & ~(ept::page_size_1g - 1U)); }

uintptr_t align_2m(uintptr_t addr)
{ return (addr & ~(ept::page_size_2m - 1U)); }

uintptr_t align_4k(uintptr_t addr)
{ return (addr & ~(ept::page_size_4k - 1U)); }

uint64_t
eptp(memory_map &map)
{
    uint64_t val = 0;
    auto pml4_hpa = map.hpa();

    eptp::memory_type::set(val, eptp::memory_type::write_back);
    eptp::page_walk_length_minus_one::set(val, max_page_walk_length - 1U);
    eptp::accessed_and_dirty_flags::disable(val);
    eptp::phys_addr::set(val, pml4_hpa);

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

//--------------------------------------------------------------------------
// Best fit
//--------------------------------------------------------------------------

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

    for (; i < end_2m; i += ept::page_size_2m) {
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

void
map_bestfit_2m(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
               memory_attr_t mattr)
{
    // If the whole range < 2MB, map all at a smaller granularity
    if (gpa_e - gpa_s < ept::page_size_2m - 1) {
        ept::map_range_4k(mem_map, gpa_s, gpa_e, hpa, mattr);
        return;
    }

    auto current_gpa = gpa_s;
    auto current_hpa = hpa;

    // Map the region starting at gpa_s that is not aligned to 2MB
    if (align_2m(current_gpa) != current_gpa) {
        const auto next_2m = align_2m(current_gpa) + ept::page_size_2m;
        const auto offset = next_2m - current_gpa;

        ept::map_range_4k(mem_map, current_gpa, next_2m - 1, current_hpa, mattr);
        current_gpa += offset;
        current_hpa += offset;
    }

    // Map the "middle" 2MB aligned page(s)
    if (gpa_e - current_gpa >= ept::page_size_2m - 1) {
        auto last_2m = align_2m(gpa_e);
        if (align_2m(current_gpa) < last_2m && gpa_e - last_2m < ept::page_size_2m - 1) {
            last_2m -= ept::page_size_2m;
        }

        ept::map_range_2m(mem_map, current_gpa, last_2m, current_hpa, mattr);

        const auto offset = (last_2m - current_gpa) + ept::page_size_2m;
        current_gpa += offset;
        current_hpa += offset;
    }

    // Map the "tail" region smaller than 2MB
    if (current_gpa < gpa_e) {
        ept::map_range_4k(mem_map, current_gpa, gpa_e, current_hpa, mattr);
    }
}

void
map_bestfit_1g(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
               memory_attr_t mattr)
{
    // If the whole range < 1G, map all at a smaller granularity
    if (gpa_e - gpa_s < ept::page_size_1g - 1) {
        ept::map_bestfit_2m(mem_map, gpa_s, gpa_e, hpa, mattr);
        return;
    }

    auto current_gpa = gpa_s;
    auto current_hpa = hpa;

    // Map the region starting at gpa_s that is not aligned to 1GB
    if (align_1g(current_gpa) != current_gpa) {
        const auto next_1g = align_1g(current_gpa) + ept::page_size_1g;
        const auto offset = next_1g - current_gpa;

        ept::map_bestfit_2m(mem_map, current_gpa, next_1g - 1, current_hpa, mattr);
        current_gpa += offset;
        current_hpa += offset;
    }

    // Map the "middle" 1GB aligned page(s)
    if (gpa_e - current_gpa >= ept::page_size_1g - 1) {
        auto last_1g = align_1g(gpa_e);
        if (align_1g(current_gpa) < last_1g && gpa_e - last_1g < ept::page_size_1g - 1) {
            last_1g -= ept::page_size_1g;
        }

        ept::map_range_1g(mem_map, current_gpa, last_1g, current_hpa, mattr);

        const auto offset = (last_1g - current_gpa) + ept::page_size_1g;
        current_gpa += offset;
        current_hpa += offset;
    }

    // Map the "tail" region smaller than 1GB
    if (current_gpa < gpa_e) {
        ept::map_bestfit_2m(mem_map, current_gpa, gpa_e, current_hpa, mattr);
    }
}

void
map_bestfit(ept::memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa,
            memory_attr_t mattr)
{
    const auto msr = ::intel_x64::msrs::ia32_vmx_ept_vpid_cap::get();

    auto max_page_size = ept::page_size_4k;
    if (::intel_x64::msrs::ia32_vmx_ept_vpid_cap::pdpte_1gb_support::is_enabled(msr)) {
        max_page_size = ept::page_size_1g;
    }
    else if (::intel_x64::msrs::ia32_vmx_ept_vpid_cap::pde_2mb_support::is_enabled(msr)) {
        max_page_size = ept::page_size_2m;
    }

    switch (max_page_size) {
        case ept::page_size_1g:
            map_bestfit_1g(mem_map, gpa_s, gpa_e, hpa, mattr);
            break;
        case ept::page_size_2m:
            map_bestfit_2m(mem_map, gpa_s, gpa_e, hpa, mattr);
            break;
        default:
            ept::map_range_4k(mem_map, gpa_s, gpa_e, hpa, mattr);
    }
}

//--------------------------------------------------------------------------
// High-level
//--------------------------------------------------------------------------

void
map(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e, hpa_t hpa)
{
    auto range_list = g_mtrrs->range_list();
    auto current_gpa = gpa_s;
    auto current_hpa = hpa;
    memory_attr_t mattr = epte::memory_attr::wb_pt;

    for (auto range : *range_list) {
        auto range_end = range.base + range.size - 1;

        if (current_gpa >= range.base && current_gpa < range_end) {
            ept::epte::memory_type::set(mattr, range.type);

            if (gpa_e < range_end) {
                map_bestfit(mem_map, current_gpa, gpa_e, current_hpa, mattr);
                return;
            }
            else {
                map_bestfit(mem_map, current_gpa, range_end, current_hpa, mattr);
                current_gpa += range.size;
                current_hpa += range.size;
            }
        }
    }

    ensures(current_gpa >= gpa_e);
}

void
identity_map(memory_map &mem_map, gpa_t gpa_s, gpa_t gpa_e)
{ map(mem_map, gpa_s, gpa_e, gpa_s); }

//--------------------------------------------------------------------------
// Unmapping
//--------------------------------------------------------------------------

void
unmap(memory_map &mem_map, gpa_t gpa)
{ mem_map.unmap(gpa); }

}
}
}
