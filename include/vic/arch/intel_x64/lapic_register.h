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
///     canonical offset = (msr_addr & ~::intel_x64::lapic::x2apic_base)
///
/// or from a memory address:
///
///     canonical offset = (mem_addr & (::x64::page_size - 1)) >> 4
///
/// Note that this mapping is _not_ invertible, meaning that in
/// general you cannot always reconstruct a valid x2APIC (MSR) or
/// xAPIC (MMIO) register address given a canonical offset.
/// Users should always check the valid operations before
/// accessing the APIC with it.
///
namespace lapic_register
{
    using attr_t = uint8_t;
    using offset_t = uint64_t;

    constexpr const auto count = (::intel_x64::lapic::x2apic_last -
        ::intel_x64::lapic::x2apic_base) + 1U;

    extern std::array<attr_t, count> attributes;

    constexpr inline auto mem_addr_to_offset(uint64_t mem_addr)
    { return (mem_addr & (::x64::page_size - 1U)) >> 4U; }

    constexpr inline auto msr_addr_to_offset(uint64_t msr_addr)
    { return (msr_addr & ~::intel_x64::lapic::x2apic_base); }

    constexpr inline auto offset_to_mem_addr(
        offset_t offset, uintptr_t base = ::intel_x64::lapic::xapic_default_base)
    { return base | (offset << 4U); }

    constexpr inline auto offset_to_msr_addr(offset_t offset)
    { return ::intel_x64::lapic::x2apic_base | offset; }

    namespace xapic_readable
    {
        constexpr const auto mask = 0x08U;
        constexpr const auto from = 3U;
        constexpr const auto name = "xapic_readable";

        constexpr inline auto is_enabled(uint64_t reg) noexcept
        { return is_bit_set(reg, from); }

        constexpr inline auto is_disabled(uint64_t reg) noexcept
        { return is_bit_cleared(reg, from); }

        constexpr inline auto enable(uint64_t reg) noexcept
        { return set_bit(reg, from); }

        constexpr inline auto disable(uint64_t reg) noexcept
        { return clear_bit(reg, from); }

        inline void dump(int level, uint64_t reg, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(reg), msg); }
    }

    namespace xapic_writable
    {
        constexpr const auto mask = 0x04U;
        constexpr const auto from = 2U;
        constexpr const auto name = "xapic_writable";

        constexpr inline auto is_enabled(uint64_t reg) noexcept
        { return is_bit_set(reg, from); }

        constexpr inline auto is_disabled(uint64_t reg) noexcept
        { return is_bit_cleared(reg, from); }

        constexpr inline auto enable(uint64_t reg) noexcept
        { return set_bit(reg, from); }

        constexpr inline auto disable(uint64_t reg) noexcept
        { return clear_bit(reg, from); }

        inline void dump(int level, uint64_t reg, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(reg), msg); }
    }

    namespace x2apic_readable
    {
        constexpr const auto mask = 0x02U;
        constexpr const auto from = 1U;
        constexpr const auto name = "x2apic_readable";

        constexpr inline auto is_enabled(uint64_t reg) noexcept
        { return is_bit_set(reg, from); }

        constexpr inline auto is_disabled(uint64_t reg) noexcept
        { return is_bit_cleared(reg, from); }

        constexpr inline auto enable(uint64_t reg) noexcept
        { return set_bit(reg, from); }

        constexpr inline auto disable(uint64_t reg) noexcept
        { return clear_bit(reg, from); }

        inline void dump(int level, uint64_t reg, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(reg), msg); }
    }

    namespace x2apic_writable
    {
        constexpr const auto mask = 0x01U;
        constexpr const auto from = 0U;
        constexpr const auto name = "x2apic_writable";

        constexpr inline auto is_enabled(uint64_t reg) noexcept
        { return is_bit_set(reg, from); }

        constexpr inline auto is_disabled(uint64_t reg) noexcept
        { return is_bit_cleared(reg, from); }

        constexpr inline auto enable(uint64_t reg) noexcept
        { return set_bit(reg, from); }

        constexpr inline auto disable(uint64_t reg) noexcept
        { return clear_bit(reg, from); }

        inline void dump(int level, uint64_t reg, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(reg), msg); }
    }

    inline auto exists_in_x2apic(offset_t offset)
    {
        const auto reg = attributes.at(offset);

        return lapic_register::x2apic_readable::is_enabled(reg) ||
               lapic_register::x2apic_writable::is_enabled(reg);
    }

    inline auto readable_in_x2apic(offset_t offset)
    {
        const auto reg = attributes.at(offset);
        return lapic_register::x2apic_readable::is_enabled(reg);
    }

    inline auto writable_in_x2apic(offset_t offset)
    {
        const auto reg = attributes.at(offset);
        return lapic_register::x2apic_writable::is_enabled(reg);
    }
}
}
}

#endif
