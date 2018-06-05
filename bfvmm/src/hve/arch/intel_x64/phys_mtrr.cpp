//
// Bareflank Hypervisor
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

#include <array>
#include <cstdio>
#include <arch/x64/misc.h>
#include <arch/intel_x64/bit.h>
#include <arch/intel_x64/mtrr.h>
#include <hve/arch/intel_x64/mtrr.h>
#include <hve/arch/intel_x64/phys_mtrr.h>
#include <hve/arch/intel_x64/ept/helpers.h>

namespace eapis
{
namespace intel_x64
{

using namespace ::intel_x64::mtrr;

///
/// Helpers
///
static inline uint64_t fixed_range_size(uint64_t range)
{
    expects(range <= 87U);

    if (range <= 7U) {
        return 1U << 16U;
    }
    else if (range <= 23U) {
        return 1U << 14U;
    }

    return 1U << 12U;
}

static inline bool in_fixed_range(uintptr_t addr)
{ return addr < phys_mtrr::s_fixed_size; }

void
phys_mtrr::print_variable_ranges(uint64_t level) const
{
    for (auto i = 0U; i < m_variable_range.size(); ++i) {
        bfdebug_text(level, "type", type_to_cstr(m_variable_range[i].type()));
        bfdebug_subnhex(level, "base", m_variable_range[i].base());
        bfdebug_subnhex(level, "mask", m_variable_range[i].mask());
        bfdebug_subnhex(level, "size", m_variable_range[i].size());
    }
}

void
phys_mtrr::print_fixed_ranges(uint64_t level) const
{
    uint64_t size = 0U;
    uint64_t base = 0U;
    uint64_t type = m_fixed_type[0];

    for (auto i = 0U; i < m_fixed_type.size(); ++i) {
        if (type == m_fixed_type.at(i)) {
            size += fixed_range_size(i);
            continue;
        }

        bfdebug_text(level, "type", type_to_cstr(m_fixed_type[i - 1U]));
        bfdebug_subnhex(level, "base", base);
        bfdebug_subnhex(level, "last", base + (size - 1U));

        base += size;
        type = m_fixed_type.at(i);
        size = fixed_range_size(i);
    }

    if (type == m_fixed_type[m_fixed_type.size() - 1U]) {
        bfdebug_text(level, "type", type_to_cstr(type));
        bfdebug_subnhex(level, "base", base);
        bfdebug_subnhex(level, "last", base + (size - 1U));
    }
}

///
/// Implementation
///
phys_mtrr::phys_mtrr()
{
    expects(::intel_x64::mtrr::is_supported());

    const auto cap = ia32_mtrrcap::get();
    const auto num = ia32_mtrrcap::vcnt::get(cap);
    expects(num > 0U && num <= 0xFFU);

    const auto def = ia32_mtrr_def_type::get();
    expects(ia32_mtrr_def_type::e::is_enabled(def));

    m_cap = cap;
    m_def = def;
    m_pas = ::x64::cpuid::addr_size::phys::get();

    this->init_fixed_ranges();
    this->init_variable_ranges();

    bfdebug_transaction(1, [&](std::string *) {
        this->print_fixed_ranges(1);
        this->print_variable_ranges(1);
    });
}

/// Init fixed ranges
///
/// This functions creates a mapping from {0..255} to {0..87}. Each
/// mapped value is an index into a memory type table. Each conditional
/// corresponds to the set of ranges with the same granularity i.e. 64KB,
/// 16KB, and 4KB. Each value assigned to 'at(i)' is the index that byte
/// i maps to in the type array. Table 11-9 in the Intel SDM contains 88 entries,
/// and each entry can have a different memory type. Note the map
/// {0..87} -> {memory types} is provided in the fixed_type array.
///
/// As a plus, once -std=c++17 is fully integrated, this function can be
/// made constexpr.
///
void
phys_mtrr::init_fixed_ranges()
{
    for (auto i = 0U; i <= 0xFFU; ++i) {
        if (i <= 0x7FU) {
            m_fixed_range.at(i) = (i & 0x70U) >> 4U;
        }
        else if (i <= 0xBFU) {
            const uint64_t mod = 4U;
            const uint64_t base = 8U;
            const uint64_t scale = ((i & 0xF0U) >> 4U) & (mod - 1U);
            const uint64_t index = ((i & 0x0FU) >> 2U);
            m_fixed_range.at(i) = gsl::narrow_cast<uint64_t>(
                                      base + index + (scale * mod));
        }
        else if (i <= 0xFF) {
            const uint64_t mod = 16U;
            const uint64_t base = 24U;
            const uint64_t scale = (((i & 0xF0U) >> 4U) & (mod - 1U)) - 0xCU;
            const uint64_t index = i & 0x0FU;
            m_fixed_range.at(i) = gsl::narrow_cast<uint64_t>(
                                      base + index + (scale * mod));
        }
    }

    this->init_fixed_types();
}

void
phys_mtrr::init_variable_ranges()
{
    const auto vcnt = ia32_mtrrcap::vcnt::get(m_cap);
    const auto base_addr = ia32_physbase::start_addr;
    const auto mask_addr = ia32_physmask::start_addr;

    for (auto i = 0U; i < (vcnt << 1U); i += 2U) {
        const auto mask_msr = ::intel_x64::msrs::get(mask_addr + i);
        if (ia32_physmask::valid::is_disabled(mask_msr)) {
            continue;
        }
        const auto base_msr = ::intel_x64::msrs::get(base_addr + i);
        m_variable_range.push_back({base_msr, mask_msr, m_pas});
    }
}

void
phys_mtrr::init_fixed_types()
{
    const std::array<::intel_x64::msrs::field_type, 11U> addrs = {{
            fix64k_00000::addr,
            fix16k_80000::addr,
            fix16k_A0000::addr,
            fix4k_C0000::addr,
            fix4k_C8000::addr,
            fix4k_D0000::addr,
            fix4k_D8000::addr,
            fix4k_E0000::addr,
            fix4k_E8000::addr,
            fix4k_F0000::addr,
            fix4k_F8000::addr
        }
    };

    for (uint64_t i = 0U; i < addrs.size(); ++i) {
        const auto msr = ::intel_x64::msrs::get(addrs.at(i));
        constexpr auto size = 8ULL;

        for (uint64_t j = 0U; j < size; ++j) {
            const auto from = (j << 3U);
            const auto mask = 0xFFULL << from;
            m_fixed_type.at((i << 3U) + j) = get_bits(msr, mask) >> from;
        }
    }
}

uint64_t
phys_mtrr::variable_count() const
{ return ia32_mtrrcap::vcnt::get(); }

uint64_t
phys_mtrr::fixed_count() const
{ return 11U; }

bool
phys_mtrr::variable_supported() const
{ return this->variable_count() > 0U; }

bool
phys_mtrr::fixed_supported() const
{ return ia32_mtrrcap::fixed_support::is_enabled(m_cap); }

bool
phys_mtrr::wc_supported() const
{ return ia32_mtrrcap::wc_support::is_enabled(m_cap); }

bool
phys_mtrr::smrr_supported() const
{ return ia32_mtrrcap::smrr_support::is_enabled(m_cap); }

uint64_t
phys_mtrr::default_mem_type() const
{ return ia32_mtrr_def_type::type::get(m_def); }

bool
phys_mtrr::fixed_enabled() const
{
    return ia32_mtrr_def_type::e::is_enabled(m_def) &&
           ia32_mtrr_def_type::fe::is_enabled(m_def);
}

bool
phys_mtrr::enabled() const
{ return ia32_mtrr_def_type::e::is_enabled(m_def); }

uint64_t
phys_mtrr::mem_type(uintptr_t addr) const
{
    if (in_fixed_range(addr)) {
        if (GSL_LIKELY(ia32_mtrr_def_type::fe::is_enabled(m_def))) {
            const auto range = get_bits(addr, 0xFF000ULL) >> 12U;
            return m_fixed_type.at(m_fixed_range.at(range));
        }
    }

    uint64_t type_bitmap = 0U;
    for (auto i = 0U; i < m_variable_range.size(); ++i) {
        if (m_variable_range.at(i).contains(addr)) {
            type_bitmap |= (1U << m_variable_range.at(i).type());
        }
    }

    switch (::intel_x64::bit::popcnt(type_bitmap)) {
        case 0U:
            return ia32_mtrr_def_type::type::get(m_def);
        case 1U:
            return ::intel_x64::bit::bsf(type_bitmap);
        default:
            if ((type_bitmap & uncacheable_mask) != 0U) {
                return uncacheable;
            }
            else if (type_bitmap == (write_through_mask | write_back_mask)) {
                return write_through;
            }

            bferror_info(0, "Undefined MTRR overlap");
            bferror_nhex(0, "addr", addr);
            bferror_nhex(0, "type_bitmap", type_bitmap);
            throw std::runtime_error("Undefined MTRR overlap at addr " +
                                     std::to_string(addr));
    }
}

void
phys_mtrr::range_list(
    const uintptr_t base,
    const uint64_t size,
    std::vector<mtrr::range> &list) const
{
    expects(size > 0U);
    expects(size == ept::align_4k(size));
    expects(base == ept::align_4k(base));
    expects(base < (base + size));

    uint64_t pages = 0U;
    uint64_t type = this->mem_type(base);
    uint64_t prev_type = type;
    uintptr_t prev_base = base;
    constexpr const uint64_t page_size = 0x1000U;

    this->print_variable_ranges(0);

    for (uint64_t addr = base; addr < (base + size); addr += page_size) {
        type = this->mem_type(addr);
        if (type == prev_type) {
            ++pages;
            continue;
        }

        list.push_back({prev_base, pages * page_size, prev_type});

        prev_base = addr;
        prev_type = type;
        pages = 1U;
    }

    if (type != prev_type) {
        return;
    }

    list.push_back({prev_base, pages * page_size, prev_type});
}

}
}
