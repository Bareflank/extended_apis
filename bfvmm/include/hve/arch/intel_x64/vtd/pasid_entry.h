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

#ifndef VTD_PASID_ENTRY_H
#define VTD_PASID_ENTRY_H

#include <stdint.h>
#include <bfgsl.h>
#include <bfbitmanip.h>
#include <bfdebug.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vtd
{

namespace pasid_entry
{
	constexpr const auto name = "pasid_entry";

	using value_type = uint64_t;

	namespace p
	{
		constexpr const auto mask = 0x1ULL;
		constexpr const auto from = 0ULL;
		constexpr const auto name = "present";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace pwt
	{
		constexpr const auto mask = 0x8ULL;
		constexpr const auto from = 3ULL;
		constexpr const auto name = "page_level_write_through";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace pcd
	{
		constexpr const auto mask = 0x10ULL;
		constexpr const auto from = 4ULL;
		constexpr const auto name = "page_level_cache_disable";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace flpm
	{
		constexpr const auto mask = 0x600ULL;
		constexpr const auto from = 9ULL;
		constexpr const auto name = "first_level_paging_mode";

		inline auto get(const value_type &pasid_entry) noexcept
		{ return get_bits(pasid_entry, mask) >> from; }

		inline void set(value_type &pasid_entry, uint64_t val) noexcept
		{ pasid_entry = set_bits(pasid_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_entry), msg); }
	}

	namespace sre
	{
		constexpr const auto mask = 0x800ULL;
		constexpr const auto from = 11ULL;
		constexpr const auto name = "supervisor_request_enable";

		inline auto is_enabled(const value_type &pasid_entry) noexcept
		{ return is_bit_set(pasid_entry, from); }

		inline auto is_disabled(const value_type &pasid_entry) noexcept
		{ return !is_bit_set(pasid_entry, from); }

		inline void enable(value_type &pasid_entry) noexcept
		{ pasid_entry = set_bit(pasid_entry, from); }

		inline void disable(value_type &pasid_entry) noexcept
		{ pasid_entry = clear_bit(pasid_entry, from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subbool(level, name, is_enabled(pasid_entry), msg); }
	}

	namespace flptptr
	{
		constexpr const auto mask = 0xFFFFFFFFF000ULL;
		constexpr const auto from = 12ULL;
		constexpr const auto name = "first_level_page_table_translation_pointer";

		inline auto get(const value_type &pasid_entry) noexcept
		{ return get_bits(pasid_entry, mask) >> from; }

		inline void set(value_type &pasid_entry, uint64_t val) noexcept
		{ pasid_entry = set_bits(pasid_entry, mask, val << from); }

		inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
		{ bfdebug_subnhex(level, name, get(pasid_entry), msg); }
	}

	inline void dump(int level, const value_type &pasid_entry, std::string *msg = nullptr)
	{
		bfdebug_nhex(level, "pasid_entry", pasid_entry, msg);

		p::dump(level, pasid_entry, msg);
		pwt::dump(level, pasid_entry, msg);
		pcd::dump(level, pasid_entry, msg);
		flpm::dump(level, pasid_entry, msg);
		sre::dump(level, pasid_entry, msg);
		flptptr::dump(level, pasid_entry, msg);
	}
}

}
}

// *INDENT-ON*

#endif
