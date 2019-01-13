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

#ifndef LAPIC_INTEL_X64_EAPIS_H
#define LAPIC_INTEL_X64_EAPIS_H

#include <cstdint>
#include <iostream>
#include <bfbitmanip.h>

namespace eapis::intel_x64::lapic
{

//
// Each xAPIC register is 32-bits
//
using value_t = uint32_t;

inline void dump_delivery_status(int lev, value_t val, std::string *msg)
{
    const auto name = "delivery_status";
    const auto idle = 0;
    const auto pending = 1;

    if (val == idle) {
        bfdebug_subtext(lev, name, "idle", msg);
        return;
    }
    if (val == pending) {
        bfdebug_subtext(lev, name, "send_pending", msg);
        return;
    }
}

inline void dump_lvt_delivery_mode(int lev, value_t val, std::string *msg)
{
    const auto name = "delivery_mode";

    switch (val) {
        case 0: bfdebug_subtext(lev, name, "fixed", msg); break;
        case 2: bfdebug_subtext(lev, name, "smi", msg); break;
        case 4: bfdebug_subtext(lev, name, "nmi", msg); break;
        case 5: bfdebug_subtext(lev, name, "init", msg); break;
        case 7: bfdebug_subtext(lev, name, "extint", msg); break;

        default:
            bfalert_subtext(lev, name, "unknown", msg);
            bfalert_subnhex(lev, "value", val, msg);
            throw std::invalid_argument(
                "unknown delivery_mode: " + std::to_string(val));
    }
}

inline void dump_icr_delivery_mode(int lev, value_t val, std::string *msg)
{
    const auto name = "delivery_mode";

    switch (val) {
        case 0: bfdebug_subtext(lev, name, "fixed", msg); break;
        case 1: bfdebug_subtext(lev, name, "lowest_priority", msg); break;
        case 2: bfdebug_subtext(lev, name, "smi", msg); break;
        case 4: bfdebug_subtext(lev, name, "nmi", msg); break;
        case 5: bfdebug_subtext(lev, name, "init", msg); break;
        case 6: bfdebug_subtext(lev, name, "sipi", msg); break;

        default:
            bfalert_subtext(lev, name, "reserved", msg);
            bfalert_subnhex(lev, "value", val, msg);
    }
}

namespace id
{
constexpr const auto name = "apic_id";
constexpr const auto indx = (0x020U >> 2U);
constexpr const auto reset_val = 0U;

namespace apic_id
{
constexpr const auto mask = 0xFF000000U;
constexpr const auto from = 24U;
constexpr const auto name = "apic_id";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace x2apic_id
{
constexpr const auto mask = 0xFFFFFFFFU;
constexpr const auto from = 0U;
constexpr const auto name = "x2apic_id";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

// Note:
//
// We the reset_val of the version register is such that:
//      version = 0x10 (integrated APIC)
//      max_lvt_entry_minus_one = 4
//      eoi_broadcast_suppression = 0 (not supported)
//
namespace version
{
constexpr const auto name = "version";
constexpr const auto indx = (0x030U >> 2U);
constexpr const auto reset_val = 0x00040010U;

namespace version
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0ULL;
constexpr const auto name = "version";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace max_lvt_entry_minus_one
{
constexpr const auto mask = 0x00FF0000U;
constexpr const auto from = 16U;
constexpr const auto name = "max_lvt_entry_minus_one";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace eoi_broadcast_suppression
{
constexpr const auto mask = 0x01000000U;
constexpr const auto from = 24U;
constexpr const auto name = "eoi_broadcast_suppression";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val, msg);
    version::dump(lev, val, msg);
    max_lvt_entry_minus_one::dump(lev, val, msg);
    eoi_broadcast_suppression::dump(lev, val, msg);
}
}

namespace tpr
{
constexpr const auto name = "tpr";
constexpr const auto indx = (0x080U >> 2U);
constexpr const auto reset_val = 0U;

namespace tpc
{
constexpr const auto name = "tpc";
constexpr const auto mask = 0x000000F0U;
constexpr const auto from = 4U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

namespace apr
{
constexpr const auto name = "apr";
constexpr const auto indx = (0x090U >> 2U);
constexpr const auto reset_val = 0U;

namespace apc
{
constexpr const auto name = "apc";
constexpr const auto mask = 0x000000F0U;
constexpr const auto from = 4U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

namespace ppr
{
constexpr const auto name = "ppr";
constexpr const auto indx = (0x0A0U >> 2U);
constexpr const auto reset_val = 0U;

namespace ppc
{
constexpr const auto name = "ppc";
constexpr const auto mask = 0x000000F0U;
constexpr const auto from = 4U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

namespace eoi
{
constexpr const auto name = "eoi";
constexpr const auto indx = (0x0B0U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace rrd
{
constexpr const auto name = "rrd";
constexpr const auto indx = (0x0C0U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace ldr
{
constexpr const auto name = "ldr";
constexpr const auto indx = (0x0D0U >> 2U);
constexpr const auto reset_val = 0U;

namespace logical_apic_id
{
constexpr const auto name = "logical_apic_id";
constexpr const auto mask = 0xFF000000U;
constexpr const auto from = 24U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

namespace dfr
{
constexpr const auto name = "dfr";
constexpr const auto indx = (0x0E0U >> 2U);
constexpr const auto reset_val = 0xFFFFFFFFU;

namespace model
{
constexpr const auto name = "model";
constexpr const auto mask = 0xF0000000U;
constexpr const auto from = 28U;

constexpr const auto flat = 0xFU;
constexpr const auto cluster = 0x0U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}
}

namespace svr
{
constexpr const auto name = "svr";
constexpr const auto indx = (0x0F0U >> 2U);
constexpr const auto reset_val = 0x000000FFU;

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace apic_enable_bit
{
constexpr const auto mask = 0x00000100U;
constexpr const auto from = 8U;
constexpr const auto name = "apic_enable_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

namespace focus_checking
{
constexpr const auto mask = 0x00000200U;
constexpr const auto from = 9U;
constexpr const auto name = "focus_checking";

inline auto is_disabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_enabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void disable(value_t &val)
{ val = set_bit(val, from); }

inline void enable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

namespace suppress_eoi_broadcast
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "suppress_eoi_broadcast";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val, msg);
    vector::dump(lev, val, msg);
    apic_enable_bit::dump(lev, val, msg);
    focus_checking::dump(lev, val, msg);
    suppress_eoi_broadcast::dump(lev, val, msg);
}
}

namespace esr
{
constexpr const auto name = "esr";
constexpr const auto indx = (0x280U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace lvt
{

// Note:
//
// The initial state of the APIC is defined in the Intel SDM. It should
// be noted that we only provide an LVT with 5 entries, as we do not
// support the PMC or thermal sensor LVT entries.
//
constexpr const auto default_size = 0x5U;
constexpr const auto reset_val = (1U << 16U);

namespace cmci
{
constexpr const auto name = "cmci";
constexpr const auto indx = (0x2F0 >> 2U);

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_mode
{
constexpr const auto mask = 0x00000700U;
constexpr const auto from = 8U;
constexpr const auto name = "delivery_mode";

constexpr const auto fixed = 0U;
constexpr const auto smi = 2U;
constexpr const auto nmi = 4U;
constexpr const auto init = 5U;
constexpr const auto extint = 7U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_lvt_delivery_mode(lev, get(val), msg); }
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace mask_bit
{
constexpr const auto mask = 0x00010000U;
constexpr const auto from = 16U;
constexpr const auto name = "mask_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val,  msg);
    vector::dump(lev, val, msg);
    delivery_mode::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    mask_bit::dump(lev, val, msg);
}
}

namespace timer
{
constexpr const auto name = "timer";
constexpr const auto indx = (0x320 >> 2U);

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace mask_bit
{
constexpr const auto mask = 0x00010000U;
constexpr const auto from = 16U;
constexpr const auto name = "mask_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

namespace mode
{
constexpr const auto mask = 0x00060000U;
constexpr const auto from = 17U;
constexpr const auto name = "mode";

constexpr const auto one_shot = 0U;
constexpr const auto periodic = 1U;
constexpr const auto tsc_deadline = 2U;

inline auto get(value_t val)
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val)
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    switch (get(val)) {
        case one_shot:
            bfdebug_subtext(lev, name, "one-shot", msg);
            break;
        case periodic:
            bfdebug_subtext(lev, name, "periodic", msg);
            break;
        case tsc_deadline:
            bfdebug_subtext(lev, name, "TSC-deadline", msg);
            break;
        default:
            bferror_subtext(lev, name, "reserved", msg);
            bferror_subnhex(lev, "value", val, msg);
            throw std::invalid_argument(
                "reserved mode: " + std::to_string(val));
    }
}
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val, msg);
    vector::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    mask_bit::dump(lev, val, msg);
    mode::dump(lev, val, msg);
}
}

namespace lint0
{
constexpr const auto name = "lint0";
constexpr const auto indx = (0x350 >> 2U);

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_mode
{
constexpr const auto mask = 0x00000700U;
constexpr const auto from = 8U;
constexpr const auto name = "delivery_mode";

constexpr const auto fixed = 0U;
constexpr const auto smi = 2U;
constexpr const auto nmi = 4U;
constexpr const auto init = 5U;
constexpr const auto extint = 7U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_lvt_delivery_mode(lev, get(val), msg); }
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace polarity
{
constexpr const auto mask = 0x00002000U;
constexpr const auto from = 13U;
constexpr const auto name = "polarity";

constexpr const auto active_high = 0U;
constexpr const auto active_low = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == active_high) {
        bfdebug_subtext(lev, name, "active_high", msg);
        return;
    }

    bfdebug_subtext(lev, name, "active_low", msg);
}
}

namespace remote_irr
{
constexpr const auto mask = 0x00004000U;
constexpr const auto from = 14U;
constexpr const auto name = "remote_irr";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace trigger_mode
{
constexpr const auto mask = 0x00008000U;
constexpr const auto from = 15U;
constexpr const auto name = "trigger_mode";

constexpr const auto edge = 0U;
constexpr const auto level = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == edge) {
        bfdebug_subtext(lev, name, "edge", msg);
        return;
    }

    bfdebug_subtext(lev, name, "level", msg);
}
}

namespace mask_bit
{
constexpr const auto mask = 0x00010000U;
constexpr const auto from = 16U;
constexpr const auto name = "mask_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val,  msg);
    vector::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    polarity::dump(lev, val, msg);
    remote_irr::dump(lev, val, msg);
    trigger_mode::dump(lev, val, msg);
    mask_bit::dump(lev, val, msg);
}
}

namespace lint1
{
constexpr const auto name = "lint1";
constexpr const auto indx = (0x360 >> 2U);

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_mode
{
constexpr const auto mask = 0x00000700U;
constexpr const auto from = 8U;
constexpr const auto name = "delivery_mode";

constexpr const auto fixed = 0U;
constexpr const auto smi = 2U;
constexpr const auto nmi = 4U;
constexpr const auto init = 5U;
constexpr const auto extint = 7U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_lvt_delivery_mode(lev, get(val), msg); }
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace polarity
{
constexpr const auto mask = 0x00002000U;
constexpr const auto from = 13U;
constexpr const auto name = "polarity";

constexpr const auto active_high = 0U;
constexpr const auto active_low = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == active_high) {
        bfdebug_subtext(lev, name, "active_high", msg);
        return;
    }

    bfdebug_subtext(lev, name, "active_low", msg);
}
}

namespace remote_irr
{
constexpr const auto mask = 0x00004000U;
constexpr const auto from = 14U;
constexpr const auto name = "remote_irr";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace trigger_mode
{
constexpr const auto mask = 0x00008000U;
constexpr const auto from = 15U;
constexpr const auto name = "trigger_mode";

constexpr const auto edge = 0U;
constexpr const auto level = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == edge) {
        bfdebug_subtext(lev, name, "edge", msg);
        return;
    }

    bfdebug_subtext(lev, name, "level", msg);
}
}

namespace mask_bit
{
constexpr const auto mask = 0x00010000U;
constexpr const auto from = 16U;
constexpr const auto name = "mask_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val,  msg);
    vector::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    polarity::dump(lev, val, msg);
    remote_irr::dump(lev, val, msg);
    trigger_mode::dump(lev, val, msg);
    mask_bit::dump(lev, val, msg);
}
}

namespace error
{
constexpr const auto name = "error";
constexpr const auto indx = (0x370 >> 2U);

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;


inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace mask_bit
{
constexpr const auto mask = 0x00010000U;
constexpr const auto from = 16U;
constexpr const auto name = "mask_bit";

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subbool(lev, name, is_enabled(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val,  msg);
    vector::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    mask_bit::dump(lev, val, msg);
}
}
}

namespace icr_low
{
constexpr const auto name = "icr_low";
constexpr const auto indx = (0x300U >> 2U);
constexpr const auto reset_val = 0;

namespace vector
{
constexpr const auto mask = 0x000000FFU;
constexpr const auto from = 0U;
constexpr const auto name = "vector";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace delivery_mode
{
constexpr const auto mask = 0x00000700U;
constexpr const auto from = 8U;
constexpr const auto name = "delivery_mode";

constexpr const auto fixed = 0U;
constexpr const auto lowest_priority = 1U;
constexpr const auto smi = 2U;
constexpr const auto nmi = 4U;
constexpr const auto init = 5U;
constexpr const auto sipi = 6U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_icr_delivery_mode(lev, get(val), msg); }
}

namespace dest_mode
{
constexpr const auto mask = 0x00000800U;
constexpr const auto from = 11U;
constexpr const auto name = "dest_mode";

constexpr const auto physical = 0U;
constexpr const auto logical = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == physical) {
        bfdebug_subtext(lev, name, "physical", msg);
        return;
    }
    bfdebug_subtext(lev, name, "logical", msg);
}
}

namespace delivery_status
{
constexpr const auto mask = 0x00001000U;
constexpr const auto from = 12U;
constexpr const auto name = "delivery_status";

constexpr const auto idle = 0U;
constexpr const auto send_pending = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ dump_delivery_status(lev, get(val), msg); }
}

namespace level
{
constexpr const auto mask = 0x00004000U;
constexpr const auto from = 14U;
constexpr const auto name = "level";

constexpr const auto deassert = 0U;
constexpr const auto assert = 1U;

inline auto is_enabled(value_t val)
{ return is_bit_set(val, from); }

inline auto is_disabled(value_t val)
{ return is_bit_cleared(val, from); }

inline void enable(value_t &val)
{ val = set_bit(val, from); }

inline void disable(value_t &val)
{ val = clear_bit(val, from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (is_disabled(val)) {
        bfdebug_subtext(lev, name, "deassert", msg);
        return;
    }
    bfdebug_subtext(lev, name, "assert", msg);
}
}

namespace trigger_mode
{
constexpr const auto mask = 0x00008000U;
constexpr const auto from = 15U;
constexpr const auto name = "trigger_mode";

constexpr const auto edge = 0U;
constexpr const auto level = 1U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == edge) {
        bfdebug_subtext(lev, name, "edge", msg);
        return;
    }
    bfdebug_subtext(lev, name, "level", msg);
}
}

namespace dest_shorthand
{
constexpr const auto mask = 0x000C0000U;
constexpr const auto from = 18U;
constexpr const auto name = "dest_shorthand";

constexpr const auto none = 0U;
constexpr const auto self = 1U;
constexpr const auto all_incl_self = 2U;
constexpr const auto all_excl_self = 3U;

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    if (get(val) == none) {
        bfdebug_subtext(lev, name, "none", msg);
        return;
    }

    if (get(val) == self) {
        bfdebug_subtext(lev, name, "self", msg);
        return;
    }

    if (get(val) == all_incl_self) {
        bfdebug_subtext(lev, name, "all_incl_self", msg);
        return;
    }

    if (get(val) == all_excl_self) {
        bfdebug_subtext(lev, name, "all_excl_self", msg);
        return;
    }
}
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val, msg);
    vector::dump(lev, val, msg);
    delivery_mode::dump(lev, val, msg);
    delivery_status::dump(lev, val, msg);
    dest_mode::dump(lev, val, msg);
    level::dump(lev, val, msg);
    trigger_mode::dump(lev, val, msg);
    dest_shorthand::dump(lev, val, msg);
}
}

namespace icr_high
{
constexpr const auto name = "icr_high";
constexpr const auto indx = (0x310U >> 2U);
constexpr const auto reset_val = 0U;

namespace xapic_dest_field
{
constexpr const auto mask = 0xFF000000U;
constexpr const auto from = 24U;
constexpr const auto name = "xapic_dest_field";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

namespace x2apic_dest_field
{
constexpr const auto mask = 0xFFFFFFFFU;
constexpr const auto from = 0U;
constexpr const auto name = "x2apic_dest_field";

inline auto get(value_t val) noexcept
{ return get_bits(val, mask) >> from; }

inline void set(value_t &reg, value_t val) noexcept
{ reg = set_bits(reg, mask, val << from); }

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{ bfdebug_subnhex(lev, name, get(val), msg); }
}

inline void dump(int lev, value_t val, std::string *msg = nullptr)
{
    bfdebug_nhex(lev, name, val, msg);
    xapic_dest_field::dump(lev, val, msg);
    x2apic_dest_field::dump(lev, val, msg);
}
}

namespace initial_count
{
constexpr const auto name = "initial_count";
constexpr const auto indx = (0x380U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace current_count
{
constexpr const auto name = "current_count";
constexpr const auto indx = (0x390U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace divide_config
{
constexpr const auto name = "divide_config";
constexpr const auto indx = (0x3E0U >> 2U);
constexpr const auto reset_val = 0U;
}

namespace self_ipi
{
constexpr const auto name = "self_ipi";
constexpr const auto indx = (0x3F0U >> 2U);
constexpr const auto reset_val = 0U;
}

}

#endif
