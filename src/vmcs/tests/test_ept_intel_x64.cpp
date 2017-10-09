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

#include <test_support.h>
#include <catch/catch.hpp>

#include <vmcs/ept_intel_x64.h>
constexpr const ept_intel_x64::integer_pointer virt = 0x0000100000000000ULL;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("ept_intel_x64: add / remove page without touching page settings")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    eptp->add_page_4k(virt);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->add_page_4k(virt + 0x1000);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->add_page_4k(virt + 0x10000);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);

    eptp->remove_page(virt + 0x1000);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);

    eptp->remove_page(virt + 0x10000);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);
}

TEST_CASE("ept_intel_x64: add / remove page 1g")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    auto entry1 = eptp->add_page_1g(virt);
    entry1.set_read_access(true);
    CHECK(eptp->global_size() == 2);
    CHECK(eptp->global_capacity() == 512 * 1);

    auto entry2 = eptp->add_page_1g(virt + 0x100);
    entry2.set_read_access(true);
    CHECK(eptp->global_size() == 2);
    CHECK(eptp->global_capacity() == 512 * 1);

    auto entry3 = eptp->add_page_1g(virt + 0x40000000);
    entry3.set_read_access(true);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 1);

    auto entry4 = eptp->add_page_1g(virt + 0x400000000);
    entry4.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 1);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 1);

    eptp->remove_page(virt + 0x40000000);
    CHECK(eptp->global_size() == 2);
    CHECK(eptp->global_capacity() == 512 * 1);

    eptp->remove_page(virt + 0x400000000);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);
}

TEST_CASE("ept_intel_x64: add / remove page 2m")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    auto entry1 = eptp->add_page_2m(virt);
    entry1.set_read_access(true);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 2);

    auto entry2 = eptp->add_page_2m(virt + 0x100);
    entry2.set_read_access(true);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 2);

    auto entry3 = eptp->add_page_2m(virt + 0x200000);
    entry3.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 2);

    auto entry4 = eptp->add_page_2m(virt + 0x2000000);
    entry4.set_read_access(true);
    CHECK(eptp->global_size() == 5);
    CHECK(eptp->global_capacity() == 512 * 2);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 2);

    eptp->remove_page(virt + 0x200000);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 2);

    eptp->remove_page(virt + 0x2000000);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);
}

TEST_CASE("ept_intel_x64: add / remove page 4k")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    auto entry1 = eptp->add_page_4k(virt);
    entry1.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    auto entry2 = eptp->add_page_4k(virt + 0x100);
    entry2.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    auto entry3 = eptp->add_page_4k(virt + 0x1000);
    entry3.set_read_access(true);
    CHECK(eptp->global_size() == 5);
    CHECK(eptp->global_capacity() == 512 * 3);

    auto entry4 = eptp->add_page_4k(virt + 0x10000);
    entry4.set_read_access(true);
    CHECK(eptp->global_size() == 6);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 5);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt + 0x1000);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt + 0x10000);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);
}

TEST_CASE("ept_intel_x64: add / remove page swap")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    auto entry1 = eptp->add_page_4k(virt);
    entry1.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);

    auto entry2 = eptp->add_page_2m(virt);
    entry2.set_read_access(true);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 2);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);

    auto entry3 = eptp->add_page_4k(virt);
    entry3.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    auto entry4 = eptp->add_page_2m(virt);
    entry4.set_read_access(true);
    CHECK(eptp->global_size() == 3);
    CHECK(eptp->global_capacity() == 512 * 2);

    auto entry5 = eptp->add_page_4k(virt);
    entry5.set_read_access(true);
    CHECK(eptp->global_size() == 4);
    CHECK(eptp->global_capacity() == 512 * 3);

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
    CHECK(eptp->global_capacity() == 512 * 1);
}

TEST_CASE("ept_intel_x64: add page twice")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    eptp->add_page_4k(virt);
    CHECK_NOTHROW(eptp->add_page_4k(virt));
}

TEST_CASE("ept_intel_x64: remove page twice")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    eptp->add_page_4k(virt);
    eptp->add_page_4k(virt + 0x1000);

    eptp->remove_page(virt);
    CHECK_NOTHROW(eptp->remove_page(virt));
    eptp->remove_page(virt + 0x1000);

    CHECK(eptp->global_size() == 0);
}

TEST_CASE("ept_intel_x64: remove unknown page")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);
    CHECK_NOTHROW(eptp->remove_page(virt));
}

TEST_CASE("ept_intel_x64: invalid gpa_to_epte")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    eptp->add_page_4k(virt);

    CHECK_THROWS(eptp->gpa_to_epte(virt + 0x40000000));

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
}

TEST_CASE("ept_intel_x64: valid gpa_to_epte")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    eptp->add_page_4k(virt);
    CHECK_NOTHROW(eptp->gpa_to_epte(virt));

    eptp->remove_page(virt);
    CHECK(eptp->global_size() == 0);
}

TEST_CASE("ept_intel_x64: ept_to_mdl")
{
    MockRepository mocks;
    setup_mm(mocks);

    ept_intel_x64::integer_pointer scr3 = 0x0ULL;
    auto eptp = std::make_unique<ept_intel_x64>(&scr3);

    CHECK(eptp->ept_to_mdl().size() == 1);
    eptp->add_page_1g(0x1000);
    CHECK(eptp->ept_to_mdl().size() == 2);
    eptp->add_page_2m(0x1000);
    CHECK(eptp->ept_to_mdl().size() == 3);
    eptp->add_page_4k(0x1000);
    CHECK(eptp->ept_to_mdl().size() == 4);

    eptp->remove_page(0x1000);
    CHECK(eptp->global_size() == 0);
}

#endif
