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

#ifndef EPT_INTRINSICS_INTEL_X64_H
#define EPT_INTRINSICS_INTEL_X64_H

#include <arch/x64/misc.h>
#include "types.h"

// *INDENT-OFF*

namespace eapis
{
namespace intel_x64
{
namespace ept
{

constexpr const uint64_t max_phys_addr = 0x0000FFFFFFFFFFFFULL;
constexpr const uint64_t max_phys_addr_msb = 47ULL;
constexpr const uint64_t max_page_walk_length = 4ULL;

constexpr const uint64_t page_size_1g = 0x40000000ULL;
constexpr const uint64_t page_size_2m = 0x200000ULL;
constexpr const uint64_t page_size_4k = 0x1000ULL;

constexpr const uint64_t epte_size_bytes = 8ULL;

namespace page_table
{
    constexpr const auto num_entries = 512UL;
    constexpr const auto size_bytes = num_entries * epte_size_bytes;
}

namespace epte
{
    namespace read_access
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "read_access";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace write_access
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "write_access";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace execute_access
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "execute_access";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace memory_type
    {
        constexpr const auto mask = 0x0000000000000038ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "memory_type";
        constexpr const auto uc = 0;
        constexpr const auto wc = 1;
        constexpr const auto wt = 4;
        constexpr const auto wp = 5;
        constexpr const auto wb = 6;

        inline auto get(epte_t &entry) noexcept
        { return get_bits(entry, mask) >> from; }

        inline void set(epte_t &entry, epte_value_t val) noexcept
        { entry = set_bits(entry, mask, val << from); }
    }

    namespace ignore_pat
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6ULL;
        constexpr const auto name = "ignore_pat";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace entry_type
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7ULL;
        constexpr const auto name = "entry_type";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace accessed_flag
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "accessed_flag";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace dirty
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "dirty";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace execute_access_user
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "execute_access_user";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace phys_addr_bits
    {
        constexpr const auto mask = 0x0000FFFFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "phys_addr";

        inline auto get(epte_t &entry) noexcept
        { return get_bits(entry, mask) >> from; }

        inline void set(epte_t &entry, epte_value_t val) noexcept
        { entry = set_bits(entry, mask, val << from); }
    }

    namespace suppress_ve
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63ULL;
        constexpr const auto name = "suppress_ve";

        inline auto is_enabled(epte_t &entry) noexcept
        { return is_bit_set(entry, from); }

        inline auto is_disabled(epte_t &entry) noexcept
        { return !is_bit_set(entry, from); }

        inline void enable(epte_t &entry) noexcept
        { entry = set_bit(entry, from); }

        inline void disable(epte_t &entry) noexcept
        { entry = clear_bit(entry, from); }
    }

    namespace memory_attr
    {
        constexpr const auto mask = 0x000000000000003FULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "memory_attr";

        constexpr const auto uc_tp = 0x00;
        constexpr const auto uc_ro = 0x01;
        constexpr const auto uc_rw = 0x03;
        constexpr const auto uc_eo = 0x04;
        constexpr const auto uc_re = 0x05;
        constexpr const auto uc_pt = 0x07;

        constexpr const auto wc_tp = 0x08;
        constexpr const auto wc_ro = 0x09;
        constexpr const auto wc_rw = 0x0B;
        constexpr const auto wc_eo = 0x0C;
        constexpr const auto wc_re = 0x0D;
        constexpr const auto wc_pt = 0x0F;

        constexpr const auto wt_tp = 0x20;
        constexpr const auto wt_ro = 0x21;
        constexpr const auto wt_rw = 0x23;
        constexpr const auto wt_eo = 0x24;
        constexpr const auto wt_re = 0x25;
        constexpr const auto wt_pt = 0x27;

        constexpr const auto wp_tp = 0x28;
        constexpr const auto wp_ro = 0x29;
        constexpr const auto wp_rw = 0x2B;
        constexpr const auto wp_eo = 0x2C;
        constexpr const auto wp_re = 0x2D;
        constexpr const auto wp_pt = 0x2F;

        constexpr const auto wb_tp = 0x30;
        constexpr const auto wb_ro = 0x31;
        constexpr const auto wb_rw = 0x33;
        constexpr const auto wb_eo = 0x34;
        constexpr const auto wb_re = 0x35;
        constexpr const auto wb_pt = 0x37;

        inline auto get(epte_t &entry) noexcept
        { return get_bits(entry, mask) >> from; }

        inline void set(epte_t &entry, epte_value_t val) noexcept
        { entry = set_bits(entry, mask, val << from); }
    }

    inline void trap_on_access(epte_t &entry) noexcept
    {
        read_access::disable(entry);
        write_access::disable(entry);
        execute_access::disable(entry);
    }

    inline void pass_through_access(epte_t &entry) noexcept
    {
        read_access::enable(entry);
        write_access::enable(entry);
        execute_access::enable(entry);
    }

    // An epte is considered "present" if any bits 2:0 or bit 10 is set
    inline bool is_present(epte_t &entry) noexcept
    { return entry & 0x407 ? true : false; }

    // Return true if the given entry maps a page frame (is a leaf entry)
    inline bool is_leaf_entry(epte_t &entry) noexcept
    { return entry_type::is_enabled(entry) ? true : false; }

    // Set all bits in the entry to 0
    inline void clear(epte_t &entry) noexcept
    { entry = 0; }

    // Returns the hpa that the physical address bits of the given entry points
    inline hpa_t hpa(epte_t &entry)
    { return (phys_addr_bits::get(entry) << phys_addr_bits::from); }

    // Set the physical address bits of the given entry to the given hpa
    inline void set_hpa(epte_t &entry, hpa_t hpa)
    { phys_addr_bits::set(entry, (hpa >> phys_addr_bits::from)); }

}

namespace gpa
{
    // Bits of a gpa that describe an index into a pml4 table
    namespace pml4_index
    {
        constexpr const auto from = 39ULL;
        constexpr const auto size = 9ULL;
        constexpr const auto mask = 0xFF8000000000ULL;
        constexpr const auto shift = 36ULL;

        inline auto get(gpa_t gpa)
        { return (gpa & mask) >> from; }

        inline auto get_offset(gpa_t gpa)
        { return (gpa & mask) >> shift; }
    }

    // Bits of a gpa that describe an offset into a page directory pointer table
    namespace pdpt_index
    {
        constexpr const auto from = 30ULL;
        constexpr const auto size = 9ULL;
        constexpr const auto mask = 0x7FC0000000ULL;
        constexpr const auto shift = 27ULL;

        inline auto get(gpa_t gpa)
        { return (gpa & mask) >> from; }

        inline auto get_offset(gpa_t gpa)
        { return (gpa & mask) >> shift; }
    }

    // Bits of a gpa that describe an offset into a page mapped by a page
    // directory pointer table entry
    namespace pdpt_page_offset
    {
        constexpr const auto from = 0ULL;
        constexpr const auto size = 30ULL;
        constexpr const auto mask = 0x3FFFFFFFULL;

        inline auto get(gpa_t gpa)
        { return gpa & mask; }
    }

    // Bits of a gpa that describe an offset into a page directory
    namespace pd_index
    {
        constexpr const auto from = 21ULL;
        constexpr const auto size = 9ULL;
        constexpr const auto mask = 0x3FE00000ULL;
        constexpr const auto shift = 18ULL;

        inline auto get(gpa_t gpa)
        { return (gpa & mask) >> from; }

        inline auto get_offset(gpa_t gpa)
        { return (gpa & mask) >> shift; }
    }

    // Bits of a gpa that describe an offset into a page mapped by a page
    // directory entry
    namespace pd_page_offset
    {
        constexpr const auto from = 0ULL;
        constexpr const auto size = 21ULL;
        constexpr const auto mask = 0x1FFFFFULL;

        inline auto get(gpa_t gpa)
        { return gpa & mask; }
    }

    // Bits of a gpa that describe an offset into a page table
    namespace pt_index
    {
        constexpr const auto from = 12ULL;
        constexpr const auto size = 9ULL;
        constexpr const auto mask = 0x1FF000ULL;
        constexpr const auto shift = 9ULL;

        inline auto get(gpa_t gpa)
        { return (gpa & mask) >> from; }

        inline auto get_offset(gpa_t gpa)
        { return (gpa & mask) >> shift; }
    }

    // Bits of a gpa that describe an offset into a page mapped by a page table
    // entry
    namespace pt_page_offset
    {
        constexpr const auto from = 0ULL;
        constexpr const auto size = 12ULL;
        constexpr const auto mask = 0xFFFULL;

        inline auto get(gpa_t gpa)
        { return gpa & mask; }
    }
}

// 512 GB per page entries not supported
namespace pml4e
{
    constexpr const auto size_bytes = epte_size_bytes;
    constexpr const auto page_table_level = 4ULL;

    namespace table_address
    {
        constexpr const auto from = 12ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFFFE00000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }
    }
}

// 1 GB per page entry
namespace pdpte
{
    constexpr const auto size_bytes = epte_size_bytes;
    constexpr const auto page_size_bytes = page_size_1g;
    constexpr const auto page_table_level = 3ULL;

    namespace page_address
    {
        constexpr const auto from = 30ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFC0000000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }

        inline hpa_t get_effective_address(epte_t &pdpte, gpa_t gpa)
        { return epte::hpa(pdpte) | (gpa & ept::gpa::pdpt_page_offset::mask); }
    }

    namespace table_address
    {
        constexpr const auto from = 12ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFFFFFF000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }
    }
}

// 2 MB per page entry
namespace pde
{
    constexpr const auto size_bytes = epte_size_bytes;
    constexpr const auto page_size_bytes = page_size_2m;
    constexpr const auto page_table_level = 2ULL;

    namespace page_address
    {
        constexpr const auto from = 21ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFFFE00000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }

        inline hpa_t get_effective_address(epte_t &pdpte, gpa_t gpa)
        { return epte::hpa(pdpte) | (gpa & ept::gpa::pdpt_page_offset::mask); }
    }

    namespace table_address
    {
        constexpr const auto from = 12ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFFFFFF000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }
    }
}

// 4 KB per page entry
namespace pte
{
    constexpr const auto size_bytes = epte_size_bytes;
    constexpr const auto page_size_bytes = page_size_4k;
    constexpr const auto page_table_level = 1ULL;

    namespace page_address
    {
        constexpr const auto from = 12ULL;
        constexpr const auto size = ept::max_phys_addr_msb - from;
        constexpr const auto mask = 0xFFFFFFFFF000ULL;

        inline bool is_aligned(hpa_t hpa)
        { return (hpa & ~mask) == 0; }

        inline hpa_t get_effective_address(epte_t &pdpte, gpa_t gpa)
        { return epte::hpa(pdpte) | (gpa & ept::gpa::pdpt_page_offset::mask); }
    }
}

}
}
}

#endif
