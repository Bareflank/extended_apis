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

#ifndef LAPIC_REGISTER_INTEL_X64_H
#define LAPIC_REGISTER_INTEL_X64_H

#include <array>
#include <intrinsics.h>

#include "base.h"

namespace eapis
{
namespace intel_x64
{

/// LAPIC Register
///
/// Defines the "canonical" offset of each LAPIC register along
/// with the set of valid operations in xAPIC and x2APIC mode. Each
/// canonical offset may be derived from an MSR address:
///
///     canonical offset = (msr_addr & ~0x800)
///
/// or from a memory address:
///
///     canonical offset = (mem_addr & (0x1000 - 1)) >> 4
///
/// Note that this mapping is _not_ invertible, meaning that in
/// general you cannot always reconstruct a valid x2APIC (MSR) or
/// xAPIC (MMIO) register address given a canonical offset.
/// Users should always check the valid operations before
/// accessing the APIC with it.
///
namespace lapic_register
{
    /// Lapic register attribute type
    using attr_t = uint64_t;

    /// Lapic register canonical offset type
    using offset_t = uint64_t;

    /// Total number of (x2)apic registers
    constexpr const auto count = (::intel_x64::lapic::x2apic_last -
        ::intel_x64::lapic::x2apic_base) + 1U;

    /// Array lapic register attributes
    extern std::array<attr_t, count> attributes;

    /// Mem addr to offset
    ///
    /// Convert an integer interpreted as equal to (xapic_base | mmio_offset)
    /// to a canonical offset.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mem_addr the address to convert to a canonical offset
    /// @return may or may not be a valid offset. Always check
    ///         before using to access the apic
    ///
    constexpr inline auto mem_addr_to_offset(uint64_t mem_addr)
    { return (mem_addr & (::x64::page_size - 1U)) >> 4U; }

    /// Msr addr to offset
    ///
    /// Convert an integer interpreted as equal to (x2apic_base | msr_offset)
    /// to a canonical offset.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr_addr the address to convert to a canonical offset
    /// @return may or may not be a valid offset. Always check
    ///         before using to access the apic
    ///
    constexpr inline auto msr_addr_to_offset(uint64_t msr_addr)
    { return (msr_addr & ~::intel_x64::lapic::x2apic_base); }

    /// Offset to memory address
    ///
    /// Convert an offset to the corresponding xAPIC MMIO address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the offset to convert
    /// @param base the base MMIO address of the xAPIC. Equals
    ///        0xFEE00000 by default
    /// @return may or may not be a valid xAPIC register address. Check
    ///         before using to access the apic
    ///
    constexpr inline auto offset_to_mem_addr(
        offset_t offset, uintptr_t base = ::intel_x64::lapic::xapic_default_base)
    { return base | (offset << 4U); }

    /// Offset to msr address
    ///
    /// Convert an offset to the corresponding x2APIC MSR address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param offset the offset to convert
    /// @return may or may not be a valid x2APIC register address. Check
    ///         before using to access the apic
    ///
    constexpr inline auto offset_to_msr_addr(offset_t offset)
    { return ::intel_x64::lapic::x2apic_base | offset; }

    /// @cond

    namespace xapic_unstable
    {
        constexpr const auto mask = 0x20U;
        constexpr const auto from = 5U;
        constexpr const auto name = "xapic_unstable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    namespace x2apic_unstable
    {
        constexpr const auto mask = 0x10U;
        constexpr const auto from = 4U;
        constexpr const auto name = "x2apic_unstable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    namespace xapic_readable
    {
        constexpr const auto mask = 0x08U;
        constexpr const auto from = 3U;
        constexpr const auto name = "xapic_readable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    namespace xapic_writable
    {
        constexpr const auto mask = 0x04U;
        constexpr const auto from = 2U;
        constexpr const auto name = "xapic_writable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    namespace x2apic_readable
    {
        constexpr const auto mask = 0x02U;
        constexpr const auto from = 1U;
        constexpr const auto name = "x2apic_readable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    namespace x2apic_writable
    {
        constexpr const auto mask = 0x01U;
        constexpr const auto from = 0U;
        constexpr const auto name = "x2apic_writable";

        constexpr inline auto is_enabled(attr_t attr) noexcept
        { return is_bit_set(attr, from); }

        constexpr inline auto is_disabled(attr_t attr) noexcept
        { return is_bit_cleared(attr, from); }

        constexpr inline auto enable(attr_t attr) noexcept
        { return set_bit(attr, from); }

        constexpr inline auto disable(attr_t attr) noexcept
        { return clear_bit(attr, from); }

        inline void dump(int level, attr_t attr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(attr), msg); }
    }

    inline auto exists_in_x2apic(offset_t offset)
    {
        const auto attr = attributes.at(offset);

        return lapic_register::x2apic_readable::is_enabled(attr) ||
               lapic_register::x2apic_writable::is_enabled(attr);
    }

    inline auto readable_in_x2apic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::x2apic_readable::is_enabled(attr);
    }

    inline auto writable_in_x2apic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::x2apic_writable::is_enabled(attr);
    }

    inline auto stable_in_x2apic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::x2apic_unstable::is_disabled(attr);
    }

    inline auto exists_in_xapic(offset_t offset)
    {
        const auto attr = attributes.at(offset);

        return lapic_register::xapic_readable::is_enabled(attr) ||
               lapic_register::xapic_writable::is_enabled(attr);
    }

    inline auto readable_in_xapic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::xapic_readable::is_enabled(attr);
    }

    inline auto writable_in_xapic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::xapic_writable::is_enabled(attr);
    }

    inline auto stable_in_xapic(offset_t offset)
    {
        const auto attr = attributes.at(offset);
        return lapic_register::xapic_unstable::is_disabled(attr);
    }

    extern void init_attributes() noexcept;

    /// @endcond
}
}
}

#endif
