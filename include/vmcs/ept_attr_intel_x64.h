//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef EPT_ATTR_INTEL_X64_H
#define EPT_ATTR_INTEL_X64_H

namespace intel_x64
{
namespace ept
{

namespace memory_attr
{
using attr_type = uint64_t;

// Read / Write
constexpr const auto rw_uc            = 0x00000100UL;
constexpr const auto rw_wc            = 0x00000101UL;
constexpr const auto rw_wt            = 0x00000104UL;
constexpr const auto rw_wp            = 0x00000105UL;
constexpr const auto rw_wb            = 0x00000106UL;

// Read / Execute
constexpr const auto re_uc            = 0x00000200UL;
constexpr const auto re_wc            = 0x00000201UL;
constexpr const auto re_wt            = 0x00000204UL;
constexpr const auto re_wp            = 0x00000205UL;
constexpr const auto re_wb            = 0x00000206UL;

// Execute Only (not support on all hardware)
constexpr const auto eo_uc            = 0x00000300UL;
constexpr const auto eo_wc            = 0x00000301UL;
constexpr const auto eo_wt            = 0x00000304UL;
constexpr const auto eo_wp            = 0x00000305UL;
constexpr const auto eo_wb            = 0x00000306UL;

// Pass Through All Accesses
constexpr const auto pt_uc            = 0x00000400UL;
constexpr const auto pt_wc            = 0x00000401UL;
constexpr const auto pt_wt            = 0x00000404UL;
constexpr const auto pt_wp            = 0x00000405UL;
constexpr const auto pt_wb            = 0x00000406UL;

// Trap on All Accesses
constexpr const auto tp_uc            = 0x00000500UL;
constexpr const auto tp_wc            = 0x00000501UL;
constexpr const auto tp_wt            = 0x00000504UL;
constexpr const auto tp_wp            = 0x00000505UL;
constexpr const auto tp_wb            = 0x00000506UL;
}

}
}

#endif
