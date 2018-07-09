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

// TIDY_EXCLUSION=-performance-move-const-arg
//
// Reason:
//     Tidy complains that the std::move(d)'s used in the add_handler calls
//     have no effect. Removing std::move however results in a compiler error
//     saying the lvalue (d) can't bind to the rvalue.
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro-bounds-pointer-arithmetic
//
// Reason:
//     The correctness of the pointer arith
//

#include <array>
#include <algorithm>

#include <arch/x64/misc.h>
#include <arch/intel_x64/cpuid.h>
#include <hve/arch/intel_x64/mtrr.h>
#include <hve/arch/intel_x64/phys_mtrr.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

using namespace ::x64::cpuid;
using namespace ::intel_x64::cpuid;
using namespace ::intel_x64::mtrr;
using namespace eapis::intel_x64::mtrr;

static const std::array<uint64_t, 5U> mtrr_type = {{
        uncacheable,
        write_combining,
        write_through,
        write_protected,
        write_back
    }
};

static const std::array<::intel_x64::msrs::field_type, 11U> fixed_addrs = {{
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

void enable_mtrr()
{
    g_edx_cpuid[feature_information::addr] |=
        feature_information::edx::mtrr::mask;  // expose through cpuid
    g_eax_cpuid[addr_size::addr] = 39U;        // phys addr size

    ia32_mtrr_def_type::e::enable();           // enable MTRRs
    ia32_mtrr_def_type::fe::enable();          // enable fixed ranges

    g_msrs[ia32_mtrrcap::addr] = (1U << 11U);  // enable smrr support
    g_msrs[ia32_mtrrcap::addr] |= (1U << 10U); // enable wc support
    g_msrs[ia32_mtrrcap::addr] |= (1U << 8U);  // enable fixed support
    g_msrs[ia32_mtrrcap::addr] |= 1U;          // set vcnt to 1

    uint64_t base = 0x800000U;
    uint64_t mask = size_to_mask(0x1000U, 39U) | (1U << 11U);

    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    ::intel_x64::msrs::set(ia32_physmask::start_addr, mask);
}

static void init_multi_fixed()
{
    expects(mtrr_type.size() == 5U);

    uint64_t val = 0U;
    for (auto j = 0U; j < mtrr_type.size(); ++j) {
        val |= mtrr_type.at(j) << (j << 3U);
    }

    ::intel_x64::msrs::set(fix64k_00000::addr, val);
    ::intel_x64::msrs::set(fix16k_80000::addr, val);
    ::intel_x64::msrs::set(fix16k_A0000::addr, val);
    ::intel_x64::msrs::set(fix4k_C0000::addr, val);
    ::intel_x64::msrs::set(fix4k_C8000::addr, val);
    ::intel_x64::msrs::set(fix4k_D0000::addr, val);
    ::intel_x64::msrs::set(fix4k_D8000::addr, val);
    ::intel_x64::msrs::set(fix4k_E0000::addr, val);
    ::intel_x64::msrs::set(fix4k_E8000::addr, val);
    ::intel_x64::msrs::set(fix4k_F0000::addr, val);
    ::intel_x64::msrs::set(fix4k_F8000::addr, val);
}

static bool
check_fixed_ranges(
    phys_mtrr &&mtrr, const std::vector<uint64_t> &base, size_t size)
{
    for (auto b : base) {
        for (uint64_t i = 0U; i < 8U; ++i) {
            uint64_t addr = b + (i * size);
            if (i < 5U) {
                if (mtrr.mem_type(addr) != mtrr_type.at(i)) {
                    return false;
                }
                continue;
            }

            if (mtrr.mem_type(addr) != uncacheable) {
                return false;
            }
        }
    }

    return true;
}

static bool check_64kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto size = (1U << 16U);
    std::vector<uint64_t> base = {0x00000U};

    return check_fixed_ranges(std::move(mtrr), base, size);
}

static bool check_16kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto size = (1U << 14U);
    std::vector<uint64_t> base = {0x80000U, 0xA0000U};

    return check_fixed_ranges(std::move(mtrr), base, size);
}

static bool check_4kb_ranges(phys_mtrr &&mtrr)
{
    constexpr auto size = (1U << 12U);
    std::vector<uint64_t> base = {
        0xC0000U, 0xC8000U, 0xD0000U, 0xD8000U,
        0xE0000U, 0xE8000U, 0xF0000U, 0xF8000U
    };

    return check_fixed_ranges(std::move(mtrr), base, size);
}

TEST_CASE("phys_mtrr: constructor")
{
    g_edx_cpuid[feature_information::addr] = 0U;
    CHECK_THROWS(phys_mtrr());

    g_edx_cpuid[feature_information::addr] = ~0U;
    ia32_mtrr_def_type::e::disable();
    CHECK_THROWS(phys_mtrr());

    ia32_mtrr_def_type::e::enable();
    g_eax_cpuid[addr_size::addr] = 0U;
    CHECK_THROWS(phys_mtrr());

    g_eax_cpuid[addr_size::addr] = 39U;
    uint64_t base = 0xFFFFFFFFFFFFFFFFU;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    CHECK_THROWS(phys_mtrr());

    uint64_t mask = 0xFFFFFFFFFFFFFFFFU;
    base = 0x10000U;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    ::intel_x64::msrs::set(ia32_physmask::start_addr, mask);
    CHECK_THROWS(phys_mtrr());

    base |= 0xFFU;
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    CHECK_THROWS(phys_mtrr());

    base = 0x800000U;
    mask = size_to_mask(0x1000U, 39U) | (1U << 11U);
    ::intel_x64::msrs::set(ia32_physbase::start_addr, base);
    ::intel_x64::msrs::set(ia32_physmask::start_addr, mask);

    g_msrs[ia32_mtrrcap::addr] = 1U;
    ia32_mtrr_def_type::type::set(write_back);
    CHECK_NOTHROW(phys_mtrr());
}

TEST_CASE("phys_mtrr: ia32_mtrrcap fields")
{
    enable_mtrr();
    auto mtrr = phys_mtrr();

    CHECK(mtrr.variable_count() == 1U);
    CHECK(mtrr.fixed_count() == 88U);
    CHECK(mtrr.enabled());
    CHECK(mtrr.fixed_enabled());
    CHECK(mtrr.wc_supported());
    CHECK(mtrr.fixed_supported());
    CHECK(mtrr.smrr_supported());
}

TEST_CASE("phys_mtrr: mem_type - fixed, single type")
{
    enable_mtrr();

    for (const uint64_t type : mtrr_type) {
        for (auto i = 0U; i < 11U; ++i) {
            uint64_t val = 0U;

            /// Assign the same type to all ranges
            for (uint64_t j = 0U; j < 8U; ++j) {
                val |= type << (j << 3U);
            }
            ::intel_x64::msrs::set(fixed_addrs.at(i), val);
        }

        auto mtrr = phys_mtrr();
        CHECK(mtrr.fixed_enabled());

        for (auto i = 0U; i < mtrr::fixed_size; i += 0x1000U) {
            CHECK(mtrr.mem_type(i) == type);
        }
    }
}

TEST_CASE("phys_mtrr: mem_type - fixed, 64KB, multi-type")
{
    enable_mtrr();
    init_multi_fixed();
    auto mtrr = phys_mtrr();

    CHECK(mtrr.fixed_enabled());
    CHECK(check_64kb_ranges(std::move(mtrr)));
    CHECK(check_16kb_ranges(std::move(mtrr)));
    CHECK(check_4kb_ranges(std::move(mtrr)));
}

TEST_CASE("phys_mtrr: mem_type - variable")
{
    enable_mtrr();

    uint64_t physbase = 0U;
    uint64_t physmask = 0U;
    uint64_t pas = g_eax_cpuid[addr_size::addr];
    uint64_t mask = size_to_mask(0x2000U, pas);

    ia32_physbase::physbase::set(physbase, 0x800000U, pas);
    ia32_physmask::physmask::set(physmask, mask, pas);
    ia32_physmask::valid::enable(physmask);

    msrs_n::set(ia32_physmask::start_addr, physmask);
    std::array<uint64_t, 3U> invalid_mtrr_type = {2U, 3U, 7U};

    for (auto type : invalid_mtrr_type) {
        ia32_physbase::type::set(physbase, type);
        msrs_n::set(ia32_physbase::start_addr, physbase);
        CHECK_THROWS(phys_mtrr());
    }

    for (auto type : mtrr_type) {
        ia32_physbase::type::set(physbase, type);
        msrs_n::set(ia32_physbase::start_addr, physbase);

        auto mtrr = phys_mtrr();
        CHECK(mtrr.mem_type(0x800000000U) == type);
    }
}

TEST_CASE("phys_mtrr: range_list - variable")
{
    enable_mtrr();
    init_multi_fixed();
    auto mtrr = phys_mtrr();
    auto list = mtrr.range_list();
    CHECK(list->size() == 59U);

    auto cmp = [](const range & lhs, const range & rhs)
    { return lhs.base < rhs.base; };

    CHECK(std::is_sorted(list->begin(), list->end(), cmp));

    CHECK(list->at(56).base == mtrr::fixed_size);
    CHECK(list->at(56).size == list->at(57).base - list->at(56).base);
    CHECK(list->at(56).type == ia32_mtrr_def_type::type::get());

    CHECK(list->at(57).base == 0x800000U);
    CHECK(list->at(57).size == 0x1000U);
    CHECK(list->at(57).type == uncacheable);

    CHECK(list->at(58).base == list->at(57).base + list->at(57).size);
    CHECK(list->at(58).type == ia32_mtrr_def_type::type::get());
}

TEST_CASE("phys_mtrr: range_list - 64KB")
{
    enable_mtrr();
    init_multi_fixed();
    auto mtrr = phys_mtrr();
    auto list = mtrr.range_list();

    CHECK(list->size() == 59U);

    for (auto i = 0U; i < 6U; ++i) {
        CHECK(list->at(i).base == i * (1U << 16U));
        CHECK(list->at(i).type == mtrr_type.at(i % 5U));

        if (i < 5U) {
            CHECK(list->at(i).size == (1U << 16U));
            continue;
        }
        CHECK(list->at(i).size == 3 * (1U << 16U) + (1U << 14U));
    }
}

TEST_CASE("phys_mtrr: range_list - 16KB")
{
    enable_mtrr();
    init_multi_fixed();
    auto mtrr = phys_mtrr();
    auto list = mtrr.range_list();

    CHECK(list->size() == 59U);
    uint64_t base = list->at(5U).base + list->at(5U).size;

    for (auto i = 6U; i < 11U; ++i) {
        CHECK(list->at(i).base == base + (i - 6U) * (1U << 14U));
        CHECK(list->at(i).type == mtrr_type.at(i % 5U));

        if (i < 10U) {
            CHECK(list->at(i).size == (1U << 14U));
            continue;
        }
        CHECK(list->at(i).size == 4 * (1U << 14U));
    }

    base = list->at(10).base + list->at(10).size;

    for (auto i = 11U; i < 16U; ++i) {
        CHECK(list->at(i).base == base + (i - 11U) * (1U << 14U));
        CHECK(list->at(i).type == mtrr_type.at(i % 5U));

        if (i < 15U) {
            CHECK(list->at(i).size == (1U << 14U));
            continue;
        }
        CHECK(list->at(i).size == 3 * (1U << 14U) + (1U << 12U));
    }
}

TEST_CASE("phys_mtrr: range_list - 4KB")
{
    enable_mtrr();
    init_multi_fixed();
    auto mtrr = phys_mtrr();
    auto list = mtrr.range_list();

    CHECK(list->size() == 59U);

    for (auto i = 16U; i < 56U; ++i) {
        if (i % 5U != 0U) {
            uint64_t k = (i / 5U) * 5U;
            uint64_t base = list->at(k).base + list->at(k).size;
            CHECK(list->at(i).base == base + ((i % 5U) - 1U) * (1U << 12U));
            CHECK(list->at(i).type == mtrr_type.at(i % 5U));
            CHECK(list->at(i).size == (1U << 12U));
        }
        else {
            uint64_t base = list->at(i - 1U).base + list->at(i - 1U).size;
            CHECK(list->at(i).base == base);
            CHECK(list->at(i).type == uncacheable);
            if (i != 55U) {
                CHECK(list->at(i).size == 4U * (1U << 12U));
            }
            else {
                CHECK(list->at(i).size == 3U * (1U << 12U));
            }
        }
    }
}

}
}

#endif
