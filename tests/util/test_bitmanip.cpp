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

#include <catch/catch.hpp>
#include "../../include/util/bitmanip.h"

TEST_CASE("bitmanip_eapis: set bit from span")
{
    auto buf = std::make_unique<unsigned[]>(10);
    auto buf_view = gsl::make_span(buf, 10);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 0);
    CHECK(buf_view[0] == 0x1);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 8);
    CHECK(buf_view[0] == 0x100);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 48);
    CHECK(buf_view[1] == 0x10000);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    CHECK_THROWS(set_bit_from_span(buf_view, 1000000));
}

TEST_CASE("bitmanip_eapis: clear bit from span")
{
    auto buf = std::make_unique<unsigned[]>(10);
    auto buf_view = gsl::make_span(buf, 10);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit_from_span(buf_view, 0);
    CHECK(buf_view[0] == 0xFFFFFFFE);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit_from_span(buf_view, 8);
    CHECK(buf_view[0] == 0xFFFFFEFF);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    clear_bit_from_span(buf_view, 48);
    CHECK(buf_view[1] == 0xFFFEFFFF);

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    CHECK_THROWS(clear_bit_from_span(buf_view, 1000000));
}

TEST_CASE("bitmanip_eapis: is bit")
{
    auto buf = std::make_unique<unsigned[]>(10);
    auto buf_view = gsl::make_span(buf, 10);

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 0);
    CHECK(is_bit_set_from_span(buf_view, 0));
    CHECK(!is_bit_cleared_from_span(buf_view, 0));

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 8);
    CHECK(is_bit_set_from_span(buf_view, 8));
    CHECK(!is_bit_cleared_from_span(buf_view, 8));

    memset(buf.get(), 0, 10 * sizeof(unsigned));
    set_bit_from_span(buf_view, 48);
    CHECK(is_bit_set_from_span(buf_view, 48));
    CHECK(!is_bit_cleared_from_span(buf_view, 48));

    memset(buf.get(), 0xFF, 10 * sizeof(unsigned));
    CHECK_THROWS(is_bit_set_from_span(buf_view, 1000000));
    CHECK_THROWS(is_bit_cleared_from_span(buf_view, 1000000));
}
