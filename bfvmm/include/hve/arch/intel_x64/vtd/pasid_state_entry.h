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

#ifndef VTD_PASID_STATE_ENTRY_H
#define VTD_PASID_STATE_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pasid_state_entry
{
	constexpr const auto name = "pasid_state_entry";

	using value_type = uint64_t;

	namespace arefcnt
	{
		constexpr const auto mask = 0xFFFF00000000ULL;
		constexpr const auto from = 32ULL;
		constexpr const auto name = "active_reference_count";

		inline auto get(const value_type &pasid_state_entry) noexcept
		{ return get_bits(pasid_state_entry, mask) >> from; }

		inline void set(value_type &pasid_state_entry, uint64_t val) noexcept
		{ pasid_state_entry = set_bits(pasid_state_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_state_entry), msg); }
	}

	namespace dinv
	{
		constexpr const auto mask = 0x8000000000000000ULL;
		constexpr const auto from = 63ULL;
		constexpr const auto name = "deferred_invalidate";

		inline auto is_enabled(const value_type &pasid_state_entry) noexcept
		{ return is_bit_set(pasid_state_entry, from); }

		inline auto is_disabled(const value_type &pasid_state_entry) noexcept
		{ return !is_bit_set(pasid_state_entry, from); }

		inline void enable(value_type &pasid_state_entry) noexcept
		{ pasid_state_entry = set_bit(pasid_state_entry, from); }

		inline void disable(value_type &pasid_state_entry) noexcept
		{ pasid_state_entry = clear_bit(pasid_state_entry, from); }

		inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_state_entry), msg); }
	}

	inline void dump(int level, const value_type &pasid_state_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pasid_state_entry", pasid_state_entry, msg);

		arefcnt::dump(level, pasid_state_entry, msg);
		dinv::dump(level, pasid_state_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
