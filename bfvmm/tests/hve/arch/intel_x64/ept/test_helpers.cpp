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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>
#include <hve/arch/intel_x64/ept.h>

TEST_CASE("identity_map_1g")
{
    ept::mmap mmap{};
    identity_map_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);

    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 0));
    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 1));
    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 2));
    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 4));
}

TEST_CASE("identity_map_2m")
{
    ept::mmap mmap{};
    identity_map_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);

    CHECK(mmap.is_2m(::intel_x64::ept::pd::page_size * 0));
    CHECK(mmap.is_2m(::intel_x64::ept::pd::page_size * 1));
    CHECK(mmap.is_2m(::intel_x64::ept::pd::page_size * 2));
    CHECK(mmap.is_2m(::intel_x64::ept::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 4));
}

TEST_CASE("identity_map_4k")
{
    ept::mmap mmap{};
    identity_map_4k(mmap, 0, ::intel_x64::ept::pt::page_size * 4);

    CHECK(mmap.is_4k(::intel_x64::ept::pt::page_size * 0));
    CHECK(mmap.is_4k(::intel_x64::ept::pt::page_size * 1));
    CHECK(mmap.is_4k(::intel_x64::ept::pt::page_size * 2));
    CHECK(mmap.is_4k(::intel_x64::ept::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 4));
}

TEST_CASE("identity_unmap_1g")
{
    ept::mmap mmap{};
    identity_map_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);
    identity_unmap_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);

    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 0));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 1));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 2));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 4));
}

TEST_CASE("identity_unmap_2m")
{
    ept::mmap mmap{};
    identity_map_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);
    identity_unmap_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);

    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 0));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 1));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 2));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 4));
}

TEST_CASE("identity_unmap_4k")
{
    ept::mmap mmap{};
    identity_map_4k(mmap, 0, ::intel_x64::ept::pt::page_size * 4);
    identity_unmap_4k(mmap, 0, ::intel_x64::ept::pt::page_size * 4);

    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 0));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 1));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 2));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 4));
}

TEST_CASE("identity_release_1g")
{
    ept::mmap mmap{};
    identity_map_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);
    identity_release_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);

    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 0));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 1));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 2));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::intel_x64::ept::pdpt::page_size * 4));
}

TEST_CASE("identity_release_2m")
{
    ept::mmap mmap{};
    identity_map_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);
    identity_release_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);

    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 0));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 1));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 2));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::intel_x64::ept::pd::page_size * 4));
}

TEST_CASE("identity_release_4k")
{
    ept::mmap mmap{};
    identity_map_4k(mmap, 0, ::intel_x64::ept::pt::page_size * 4);
    identity_release_4k(mmap, 0, ::intel_x64::ept::pt::page_size * 4);

    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 0));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 1));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 2));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::intel_x64::ept::pt::page_size * 4));
}

TEST_CASE("identity_map_convert_1g_to_2m")
{
    ept::mmap mmap{};
    identity_map_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);

    identity_map_convert_1g_to_2m(mmap, 0);
    CHECK(mmap.is_2m(nullptr));
    CHECK(mmap.is_2m(::intel_x64::ept::pdpt::page_size - ::intel_x64::ept::pd::page_size));

    identity_map_convert_2m_to_1g(mmap, 0);
    CHECK(mmap.is_1g(nullptr));
    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size - ::intel_x64::ept::pd::page_size));
}

TEST_CASE("identity_map_convert_1g_to_4k")
{
    ept::mmap mmap{};
    identity_map_1g(mmap, 0, ::intel_x64::ept::pdpt::page_size * 4);

    identity_map_convert_1g_to_4k(mmap, 0);
    CHECK(mmap.is_4k(nullptr));
    CHECK(mmap.is_4k(::intel_x64::ept::pdpt::page_size - ::intel_x64::ept::pd::page_size));

    identity_map_convert_4k_to_1g(mmap, 0);
    CHECK(mmap.is_1g(nullptr));
    CHECK(mmap.is_1g(::intel_x64::ept::pdpt::page_size - ::intel_x64::ept::pd::page_size));
}

TEST_CASE("identity_map_convert_2m_to_4k")
{
    ept::mmap mmap{};
    identity_map_2m(mmap, 0, ::intel_x64::ept::pd::page_size * 4);

    identity_map_convert_2m_to_4k(mmap, 0);
    CHECK(mmap.is_4k(nullptr));
    CHECK(mmap.is_4k(::intel_x64::ept::pd::page_size - ::intel_x64::ept::pt::page_size));

    identity_map_convert_4k_to_2m(mmap, 0);
    CHECK(mmap.is_2m(nullptr));
    CHECK(mmap.is_2m(::intel_x64::ept::pd::page_size - ::intel_x64::ept::pt::page_size));
}

TEST_CASE("identity_map")
{
    using range_t = mtrrs::range_t;

    enable_mtrrs(1);
    add_variable_range(0, range_t{wb, 0x100000, 0x1000});
    add_variable_range(0, range_t{wb, 0x200000, 0x400000});
    add_variable_range(0, range_t{wb, 0x600000, 0x1000});

    ept::mmap mmap{};
    identity_map(mmap, 0, 0xA00000);

    CHECK(mmap.is_4k(nullptr));
    CHECK(mmap.is_4k(0x100000));
    CHECK(mmap.is_4k(0x101000));
    CHECK(mmap.is_4k(0x1FF000));
    CHECK(mmap.is_2m(0x200000));
    CHECK(mmap.is_2m(0x400000));
    CHECK(mmap.is_4k(0x600000));
    CHECK(mmap.is_4k(0x601000));
    CHECK(mmap.is_4k(0x7FF000));
    CHECK(mmap.is_2m(0x800000));
}
