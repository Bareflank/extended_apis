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

#ifndef VTD_EXTENDED_ROOT_ENTRY_H
#define VTD_EXTENDED_ROOT_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace extended_root_entry
{
	constexpr const auto name = "extended_root_entry";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace lp
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "lower_present";

		inline auto is_enabled(const value_type &extended_root_entry) noexcept
		{ return is_bit_set(extended_root_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_root_entry) noexcept
		{ return !is_bit_set(extended_root_entry.data[index], from); }

		inline void enable(value_type &extended_root_entry) noexcept
		{ extended_root_entry.data[index] = set_bit(extended_root_entry.data[index], from); }

		inline void disable(value_type &extended_root_entry) noexcept
		{ extended_root_entry.data[index] = clear_bit(extended_root_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_root_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_root_entry), msg); }
	}

	namespace lctp
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "lower_context_table_pointer";

		inline auto get(const value_type &extended_root_entry) noexcept
		{ return get_bits(extended_root_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_root_entry, uint64_t val) noexcept
		{ extended_root_entry.data[index] = set_bits(extended_root_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_root_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_root_entry), msg); }
	}

	namespace up
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "upper_present";

		inline auto is_enabled(const value_type &extended_root_entry) noexcept
		{ return is_bit_set(extended_root_entry.data[index], from); }

		inline auto is_disabled(const value_type &extended_root_entry) noexcept
		{ return !is_bit_set(extended_root_entry.data[index], from); }

		inline void enable(value_type &extended_root_entry) noexcept
		{ extended_root_entry.data[index] = set_bit(extended_root_entry.data[index], from); }

		inline void disable(value_type &extended_root_entry) noexcept
		{ extended_root_entry.data[index] = clear_bit(extended_root_entry.data[index], from); }

		inline void dump(int level, const value_type &extended_root_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(extended_root_entry), msg); }
	}

	namespace uctp
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 1ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "upper_context_table_pointer";

		inline auto get(const value_type &extended_root_entry) noexcept
		{ return get_bits(extended_root_entry.data[index], mask) >> from; }

		inline void set(value_type &extended_root_entry, uint64_t val) noexcept
		{ extended_root_entry.data[index] = set_bits(extended_root_entry.data[index], mask, val << from); }

		inline void dump(int level, const value_type &extended_root_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(extended_root_entry), msg); }
	}

	inline void dump(int level, const value_type &extended_root_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "extended_root_entry[63:0]", extended_root_entry.data[0], msg);
		bfdebug_nhex(level, "extended_root_entry[127:64]", extended_root_entry.data[1], msg);

		lp::dump(level, extended_root_entry, msg);
		lctp::dump(level, extended_root_entry, msg);
		up::dump(level, extended_root_entry, msg);
		uctp::dump(level, extended_root_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
