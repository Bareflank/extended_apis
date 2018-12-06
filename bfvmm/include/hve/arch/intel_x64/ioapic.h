//
// Bareflank Extended APIs
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

#ifndef IOAPIC_INTEL_X64_EAPIS_H
#define IOAPIC_INTEL_X64_EAPIS_H

#include <cstdint>
#include <iostream>
#include <bfbitmanip.h>

namespace eapis::intel_x64::ioapic
{

//
// Each IOAPIC register is 32-bits, and each RTE is 64
//
// NOTE: the subfields have not been implemented yet
//

using reg_t = uint32_t;
using rte_t = uint64_t;

constexpr const auto sel_offset = 0x00;
constexpr const auto win_offset = 0x10;

namespace id
{
    constexpr const auto name = "id";
    constexpr const auto indx = 0;
    constexpr const auto mask = 0xF000000U;
    constexpr const auto from = 24;
    constexpr const auto reset_val = 0;

    inline auto get(reg_t val) noexcept
    { return get_bits(val, mask) >> from; }

    inline void set(reg_t &reg, reg_t val) noexcept
    { reg = set_bits(reg, mask, val << from); }

    inline void dump(int lev, reg_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace version
{
    constexpr const auto name = "version";
    constexpr const auto indx = 1;
    constexpr const auto reset_val = 0x00170011U;

    namespace version
    {
        constexpr const auto name = "version";
        constexpr const auto mask = 0xFFU;
        constexpr const auto from = 0;

        inline auto get(reg_t val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(reg_t &reg, reg_t val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, reg_t val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace max_rte
    {
        constexpr const auto name = "max_rte";
        constexpr const auto mask = 0xFF0000U;
        constexpr const auto from = 16;

        inline auto get(reg_t val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(reg_t &reg, reg_t val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, reg_t val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    inline void dump(int lev, reg_t val, std::string *msg = nullptr)
    {
        version::dump(lev, val, msg);
        max_rte::dump(lev, val, msg);
    }
}

namespace arbid
{
    constexpr const auto name = "arbid";
    constexpr const auto indx = 2;

    constexpr const auto mask = 0xF000000U;
    constexpr const auto from = 24;
    constexpr const auto reset_val = 0;

    inline auto get(reg_t val) noexcept
    { return get_bits(val, mask) >> from; }

    inline void set(reg_t &reg, reg_t val) noexcept
    { reg = set_bits(reg, mask, val << from); }

    inline void dump(int lev, reg_t val, std::string *msg = nullptr)
    { bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace redtbl
{
    constexpr const auto name = "redtbl";
    constexpr const auto indx = 16;
    constexpr const auto size = 24;
}
}

#endif
