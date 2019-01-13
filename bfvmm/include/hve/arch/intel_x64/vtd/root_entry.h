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

#ifndef VTD_ROOT_TABLE_ENTRY_H
#define VTD_ROOT_TABLE_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace rte
{
	constexpr const auto name = "rte";

	using value_type = struct value_type { uint64_t data[2]{0}; };

	namespace present
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &rte) noexcept
		{ return is_bit_set(rte.data[index], from); }

		inline auto is_disabled(const value_type &rte) noexcept
		{ return !is_bit_set(rte.data[index], from); }

		inline void enable(value_type &rte) noexcept
		{ rte.data[index] = set_bit(rte.data[index], from); }

		inline void disable(value_type &rte) noexcept
		{ rte.data[index] = clear_bit(rte.data[index], from); }

		inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(rte), msg); }
	}

	namespace context_table_pointer
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto index = 0ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "context_table_pointer";

		inline auto get(const value_type &rte) noexcept
		{ return get_bits(rte.data[index], mask) >> from; }

		inline void set(value_type &rte, uint64_t val) noexcept
		{ rte.data[index] = set_bits(rte.data[index], mask, val << from); }

		inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(rte), msg); }
	}

	inline void dump(int level, const value_type &rte, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "rte[63:0]", rte.data[0], msg);
		bfdebug_nhex(level, "rte[127:64]", rte.data[1], msg);

		present::dump(level, rte, msg);
		context_table_pointer::dump(level, rte, msg);
	}
}

}
}

// *INDENT-ON*

#endif
