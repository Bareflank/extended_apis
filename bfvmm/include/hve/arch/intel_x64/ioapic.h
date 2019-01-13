//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
