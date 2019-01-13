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

#ifndef VTD_POSTED_INTERRUPT_DESCRIPTOR_H
#define VTD_POSTED_INTERRUPT_DESCRIPTOR_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pid
{
	constexpr const auto name = "pid";

	using value_type = struct value_type { uint64_t data[8]{0}; };

	namespace pir
	{
		constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "posted_interrupt_requests";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	namespace on
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "outstanding_notification";

		inline auto is_enabled(const value_type &pid) noexcept
		{ return is_bit_set(pid.data[index], from); }

		inline auto is_disabled(const value_type &pid) noexcept
		{ return !is_bit_set(pid.data[index], from); }

		inline void enable(value_type &pid) noexcept
		{ pid.data[index] = set_bit(pid.data[index], from); }

		inline void disable(value_type &pid) noexcept
		{ pid.data[index] = clear_bit(pid.data[index], from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pid), msg); }
	}

	namespace sn
	{
		constexpr const auto mask = 0x2ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 1ULL;
		constexpr const auto name = "supress_notification";

		inline auto is_enabled(const value_type &pid) noexcept
		{ return is_bit_set(pid.data[index], from); }

		inline auto is_disabled(const value_type &pid) noexcept
		{ return !is_bit_set(pid.data[index], from); }

		inline void enable(value_type &pid) noexcept
		{ pid.data[index] = set_bit(pid.data[index], from); }

		inline void disable(value_type &pid) noexcept
		{ pid.data[index] = clear_bit(pid.data[index], from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pid), msg); }
	}

	namespace nv
	{
		constexpr const auto mask = 0xFF0000ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 16ULL;
		constexpr const auto name = "notification_vector";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	namespace ndst
	{
		constexpr const auto mask = 0xFFFFFFFF00000000ULL;
		constexpr const auto index = 4ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "notification_destination";

		inline auto get(const value_type &pid) noexcept
		{ return get_bits(pid.data[index], mask) >> from; }

		inline void set(value_type &pid, uint64_t val) noexcept
		{ pid.data[index] = set_bits(pid.data[index], mask, val << from); }

		inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pid), msg); }
	}

	inline void dump(int level, const value_type &pid, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pid[63:0]", pid.data[0], msg);
		bfdebug_nhex(level, "pid[127:64]", pid.data[1], msg);
		bfdebug_nhex(level, "pid[191:128]", pid.data[2], msg);
		bfdebug_nhex(level, "pid[255:192]", pid.data[3], msg);
		bfdebug_nhex(level, "pid[319:256]", pid.data[4], msg);
		bfdebug_nhex(level, "pid[383:320]", pid.data[5], msg);
		bfdebug_nhex(level, "pid[447:384]", pid.data[6], msg);
		bfdebug_nhex(level, "pid[511:448]", pid.data[7], msg);

		pir::dump(level, pid, msg);
		on::dump(level, pid, msg);
		sn::dump(level, pid, msg);
		nv::dump(level, pid, msg);
		ndst::dump(level, pid, msg);
	}
}

}
}

// *INDENT-ON*

#endif
