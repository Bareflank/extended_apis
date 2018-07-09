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
using namespace ::eapis::intel_x64::mtrr;

const std::array<::intel_x64::msrs::field_type, 11U> fixed_addr = {{
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

///
/// Helpers
///
static inline uint64_t fixed_range_size(uint64_t range)
{
    expects(range <= 87U);

    if (range <= 7U) {
        return 1ULL << 16U;
    }

    if (range <= 23U) {
        return 1ULL << 14U;
    }

    return 1ULL << 12U;
}

static inline bool in_fixed_range(uintptr_t addr)
{ return addr < mtrr::fixed_size; }

void
phys_mtrr::print_variable_ranges(uint64_t level) const
{
    for (const auto range : m_variable_range) {
        bfdebug_text(level, "type", type_to_cstr(range.type()));
        bfdebug_subnhex(level, "base", range.base());
        bfdebug_subnhex(level, "mask", range.mask());
        bfdebug_subnhex(level, "size", range.size());
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

        bfdebug_text(level, "type", type_to_cstr(m_fixed_type.at(i - 1U)));
        bfdebug_subnhex(level, "base", base);
        bfdebug_subnhex(level, "last", base + (size - 1U));

        base += size;
        type = m_fixed_type.at(i);
        size = fixed_range_size(i);
    }

    if (type == m_fixed_type.at(m_fixed_type.size() - 1U)) {
        bfdebug_text(level, "type", type_to_cstr(type));
        bfdebug_subnhex(level, "base", base);
        bfdebug_subnhex(level, "last", base + (size - 1U));
    }
}

void
phys_mtrr::print_range_list(uint64_t level) const
{
    bfdebug_info(level, "phys_mtrr range_list:");

    for (const auto &range : m_range_list) {
        bfdebug_subtext(level, "type", type_to_cstr(range.type));
        bfdebug_subnhex(level, "base", range.base);
        bfdebug_subnhex(level, "last", range.base + (range.size - 1U));
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

    this->parse_fixed_mtrrs();
    this->parse_variable_mtrrs();
    this->setup_range_list();

    bfdebug_transaction(1, [&](std::string *) {
        this->print_fixed_ranges(1);
        this->print_variable_ranges(1);
        this->print_range_list(1);
    });
}

/// Parse fixed MTRRs
///
/// This functions creates a mapping from {0..255} to {0..87}. Each
/// mapped value is one of the 88 fixed ranges. When we need the type
/// of an address in the fixed range, we can use the byte b = address[19-12]
/// as a key into the m_fixed_range array.  The value m_fixed_range[b] is the
/// range the address belongs to.
///
/// Table 11-9 in the Intel SDM contains 88 entries, and each entry can
/// have a different memory type. The m_fixed_type array maps these
/// entries to their corresponding type from the 8 fixed MTRRS.
///
/// As a plus, once -std=c++17 is integrated, this function can be
/// made mostly constexpr.
///
void
phys_mtrr::parse_fixed_mtrrs()
{
    for (uint64_t i64 = 0U; i64 <= 0xFFU; ++i64) {
        auto i = gsl::narrow_cast<uint8_t>(i64);

        if (i <= 0x7FU) {
            m_fixed_range.at(i) = (i & 0x70U) >> 4U;
        }
        else if (i <= 0xBFU) {
            const auto mod = 4U;
            const auto base = 8U;
            const auto index = gsl::narrow_cast<uint8_t>(((i & 0x0FU) >> 2U));
            const auto scale = gsl::narrow_cast<uint8_t>(((i & 0xF0U) >> 4U) & (mod - 1U));
            m_fixed_range.at(i) = gsl::narrow_cast<uint8_t>(base + index + (scale * mod));
        }
        else {
            const auto mod = 16U;
            const auto base = 24U;
            const auto index = gsl::narrow_cast<uint8_t>(i & 0x0FU);
            const auto scale = gsl::narrow_cast<uint8_t>((((i & 0xF0U) >> 4U) & (mod - 1U)) - 0xCU);
            m_fixed_range.at(i) = gsl::narrow_cast<uint8_t>(base + index + (scale * mod));
        }
    }

    for (uint64_t i = 0U; i < fixed_addr.size(); ++i) {
        const uint64_t msr = ::intel_x64::msrs::get(fixed_addr.at(i));
        for (uint64_t j = 0U; j < 8U; ++j) {
            const auto from = gsl::narrow_cast<uint8_t>(j << 3U);
            const uint64_t mask = 0xFFULL << from;
            const auto type = gsl::narrow_cast<uint8_t>(get_bits(msr, mask) >> from);
            m_fixed_type.at((i << 3U) + j) = type;
        }
    }
}

void
phys_mtrr::parse_variable_mtrrs()
{
    const uint64_t vcnt = ia32_mtrrcap::vcnt::get(m_cap);
    const ::intel_x64::msrs::field_type base_addr = ia32_physbase::start_addr;
    const ::intel_x64::msrs::field_type mask_addr = ia32_physmask::start_addr;

    for (uint32_t i = 0U; i < (vcnt << 1U); i += 2U) {
        const uint64_t mask_msr = ::intel_x64::msrs::get(mask_addr + i);
        if (ia32_physmask::valid::is_disabled(mask_msr)) {
            continue;
        }
        const uint64_t base_msr = ::intel_x64::msrs::get(base_addr + i);
        m_variable_range.emplace_back(base_msr, mask_msr, m_pas);
    }
}

uint64_t
phys_mtrr::variable_count() const
{ return ia32_mtrrcap::vcnt::get(); }

uint64_t
phys_mtrr::fixed_count() const
{ return mtrr::fixed_count; }

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
    for (const auto range : m_variable_range) {
        if (range.contains(addr)) {
            type_bitmap |= (1U << range.type());
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

            if (type_bitmap == (write_through_mask | write_back_mask)) {
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
phys_mtrr::setup_fixed_range_list()
{
    uint64_t base = 0U;
    uint64_t pages = 0U;
    uint64_t type = this->mem_type(base);
    uint64_t prev_type = type;
    constexpr const uint64_t page_size = 0x1000U;

    for (uint64_t addr = base; addr < mtrr::fixed_size; addr += page_size) {
        type = this->mem_type(addr);
        if (type == prev_type) {
            ++pages;
            continue;
        }

        m_range_list.push_back({base, pages * page_size, prev_type});
        base = addr;
        pages = 1U;
        prev_type = type;
    }

    if (type == prev_type) {
        m_range_list.push_back({base, pages * page_size, prev_type});
    }
}

void
phys_mtrr::setup_variable_range_list()
{
    const auto cmp = [](const variable_range & lhs, const variable_range & rhs)
    { return lhs.base() < rhs.base(); };

    std::sort(m_variable_range.begin(), m_variable_range.end(), cmp);

    uint64_t base = mtrr::fixed_size;
    uint64_t size = 0x00U;
    uint64_t type = 0xFFU;

    for (const auto range : m_variable_range) {
        if (base < range.base()) {
            size = range.base() - base;
            type = ia32_mtrr_def_type::type::get(m_def);
            m_range_list.push_back({base, size, type});
            base = range.base();
        }

        size = range.size();
        type = range.type();
        m_range_list.push_back({base, size, type});
        base += size;
    }

    if (GSL_LIKELY(base < (1ULL << m_pas))) {
        size = (1ULL << m_pas) - base;
        type = ia32_mtrr_def_type::type::get(m_def);
        m_range_list.push_back({base, size, type});
    }
}

void
phys_mtrr::setup_range_list()
{
    this->setup_fixed_range_list();
    this->setup_variable_range_list();

    // Ensure there is no overlap
    for (uint64_t i = 0; i < m_range_list.size() - 1; ++i) {
        const auto last = m_range_list[i].base + (m_range_list[i].size - 1);
        ensures(last < m_range_list[i + 1].base);
    }
}

const std::vector<mtrr::range> *
phys_mtrr::range_list() const
{ return &m_range_list; }

}
}
