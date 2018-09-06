//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <bfvmm/test/support.h>
#include <hve/arch/intel_x64/ept.h>

using namespace eapis::intel_x64;

TEST_CASE("mmap: constructor / destructor")
{
    {
        ept::mmap mmap{};
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: eptp")
{
    {
        ept::mmap mmap{};
        CHECK(mmap.eptp() != 0);
        CHECK(mmap.eptp() != 0);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g attribute types")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::none
                   );
        mmap.map_1g(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_only
                   );
        mmap.map_1g(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::write_only
                   );
        mmap.map_1g(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::execute_only
                   );
        mmap.map_1g(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write
                   );
        mmap.map_1g(0x60000002A, 0x60000002A,
                    ept::mmap::attr_type::read_execute
                   );
        mmap.map_1g(0x70000002A, 0x70000002A,
                    ept::mmap::attr_type::read_write_execute
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m attribute types")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::none
                   );
        mmap.map_2m(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_only
                   );
        mmap.map_2m(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::write_only
                   );
        mmap.map_2m(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::execute_only
                   );
        mmap.map_2m(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write
                   );
        mmap.map_2m(0x60000002A, 0x60000002A,
                    ept::mmap::attr_type::read_execute
                   );
        mmap.map_2m(0x70000002A, 0x70000002A,
                    ept::mmap::attr_type::read_write_execute
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k attribute types")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::none
                   );
        mmap.map_4k(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_only
                   );
        mmap.map_4k(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::write_only
                   );
        mmap.map_4k(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::execute_only
                   );
        mmap.map_4k(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write
                   );
        mmap.map_4k(0x60000002A, 0x60000002A,
                    ept::mmap::attr_type::read_execute
                   );
        mmap.map_4k(0x70000002A, 0x70000002A,
                    ept::mmap::attr_type::read_write_execute
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g memory types")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::uncacheable
                   );
        mmap.map_1g(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_combining
                   );
        mmap.map_1g(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_through
                   );
        mmap.map_1g(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_protected
                   );
        mmap.map_1g(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_back
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m memory types")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::uncacheable
                   );
        mmap.map_2m(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_combining
                   );
        mmap.map_2m(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_through
                   );
        mmap.map_2m(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_protected
                   );
        mmap.map_2m(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_back
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k memory types")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x10000002A, 0x10000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::uncacheable
                   );
        mmap.map_4k(0x20000002A, 0x20000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_combining
                   );
        mmap.map_4k(0x30000002A, 0x30000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_through
                   );
        mmap.map_4k(0x40000002A, 0x40000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_protected
                   );
        mmap.map_4k(0x50000002A, 0x50000002A,
                    ept::mmap::attr_type::read_write,
                    ept::mmap::memory_type::write_back
                   );
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice fails")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        CHECK_THROWS(mmap.map_1g(0x2A, 0x2A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice fails")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        CHECK_THROWS(mmap.map_2m(0x2A, 0x2A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice fails")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        CHECK_THROWS(mmap.map_4k(0x2A, 0x2A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g twice")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m twice")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k twice")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 1g different ranges")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.map_1g(0x10000002A, 0x10000002A);
        mmap.unmap(0x2A);
        mmap.unmap(0x10000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 2m different ranges")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        mmap.map_2m(0x10000002A, 0x10000002A);
        mmap.unmap(0x2A);
        mmap.unmap(0x10000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 4k different ranges")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        mmap.map_4k(0x10000002A, 0x10000002A);
        mmap.unmap(0x2A);
        mmap.unmap(0x10000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address")
{
    {
        ept::mmap mmap{};
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address 1g")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.unmap(0x10000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address 2m")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.unmap(0x100002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice with unmap succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.map_1g(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with unmap succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.map_2m(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with unmap succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        mmap.unmap(0x2A);
        mmap.map_4k(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: release 1g")
{
    ept::mmap mmap{};
    mmap.map_1g(0x2A, 0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m")
{
    ept::mmap mmap{};
    mmap.map_2m(0x2A, 0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k")
{
    ept::mmap mmap{};
    mmap.map_4k(0x2A, 0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 1g twice")
{
    ept::mmap mmap{};
    mmap.map_1g(0x2A, 0x2A);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m twice")
{
    ept::mmap mmap{};
    mmap.map_2m(0x2A, 0x2A);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k twice")
{
    ept::mmap mmap{};
    mmap.map_4k(0x2A, 0x2A);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release non-mapped address")
{
    ept::mmap mmap{};
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release non-mapped address 1g")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.release(0x10000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: release non-mapped address 2m")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.release(0x100002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice with release succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A);
        mmap.release(0x2A);
        mmap.map_1g(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with release succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A);
        mmap.release(0x2A);
        mmap.map_2m(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with release succeeds")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A);
        mmap.release(0x2A);
        mmap.map_4k(0x2A, 0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map twice, release once")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        mmap.map_4k(0x202A, 0x202A);
        mmap.release(0x202A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, entry")
{
    {
        ept::mmap mmap{};

        mmap.map_1g(0x102A, 0x102A);
        CHECK_NOTHROW(mmap.entry(0x102A));
        CHECK_NOTHROW(mmap.entry(0x100000));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, entry")
{
    {
        ept::mmap mmap{};

        mmap.map_2m(0x102A, 0x102A);
        CHECK_NOTHROW(mmap.entry(0x102A));
        CHECK_NOTHROW(mmap.entry(0x10000));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, entry")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_NOTHROW(mmap.entry(0x102A));
        CHECK_NOTHROW(mmap.entry(0x1000));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address")
{
    {
        ept::mmap mmap{};
        CHECK_THROWS(mmap.entry(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 1g")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.entry(0x10000002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 2m")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.entry(0x100002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 4k")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.entry(0x1002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, virt_to_phys")
{
    {
        ept::mmap mmap{};

        mmap.map_1g(0x102A, 0x102A);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x100000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, virt_to_phys")
{
    {
        ept::mmap mmap{};

        mmap.map_2m(0x102A, 0x102A);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x10000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, virt_to_phys")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x1000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address")
{
    {
        ept::mmap mmap{};
        CHECK_THROWS(mmap.virt_to_phys(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 1g")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.virt_to_phys(0x10000002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 2m")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.virt_to_phys(0x100002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 4k")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.virt_to_phys(0x1002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, from")
{
    {
        ept::mmap mmap{};

        mmap.map_1g(0x102A, 0x102A);
        CHECK(mmap.from(0x102A) == ::x64::pdpt::from);
        CHECK(mmap.from(0x100000) == ::x64::pdpt::from);
        CHECK(mmap.is_1g(0x102A));
        CHECK(!mmap.is_2m(0x102A));
        CHECK(!mmap.is_4k(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, from")
{
    {
        ept::mmap mmap{};

        mmap.map_2m(0x102A, 0x102A);
        CHECK(mmap.from(0x102A) == ::x64::pd::from);
        CHECK(mmap.from(0x10000) == ::x64::pd::from);
        CHECK(!mmap.is_1g(0x102A));
        CHECK(mmap.is_2m(0x102A));
        CHECK(!mmap.is_4k(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, from")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK(mmap.from(0x102A) == ::x64::pt::from);
        CHECK(mmap.from(0x1000) == ::x64::pt::from);
        CHECK(!mmap.is_1g(0x102A));
        CHECK(!mmap.is_2m(0x102A));
        CHECK(mmap.is_4k(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address")
{
    {
        ept::mmap mmap{};
        CHECK_THROWS(mmap.from(0x102A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 1g")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.from(0x10000002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 2m")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.from(0x100002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 4k")
{
    {
        ept::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A);
        CHECK_THROWS(mmap.from(0x1002A));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 2m to 4k")
{
    {
        ept::mmap mmap{};
        mmap.map_4k(0x102A, 0x102A);
        mmap.release(0x102A);
        mmap.map_2m(0x102A, 0x102A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 4k to 2m")
{
    {
        ept::mmap mmap{};
        mmap.map_2m(0x102A, 0x102A);
        mmap.release(0x102A);
        mmap.map_4k(0x102A, 0x102A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: 1g release desperate pages")
{
    ept::mmap mmap{};
    mmap.map_1g(0x40000000, 0x40000000);
    mmap.map_1g(0x1000000000, 0x1000000000);
    mmap.map_1g(0x200000000000, 0x200000000000);
    mmap.map_1g(0x40000000000000, 0x40000000000000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 2m release desperate pages")
{
    ept::mmap mmap{};
    mmap.map_2m(0x200000, 0x200000);
    mmap.map_2m(0x40000000, 0x40000000);
    mmap.map_2m(0x1000000000, 0x1000000000);
    mmap.map_2m(0x200000000000, 0x200000000000);
    mmap.map_2m(0x40000000000000, 0x40000000000000);
    mmap.release(0x200000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 4k release desperate pages")
{
    ept::mmap mmap{};
    mmap.map_4k(0x1000, 0x1000);
    mmap.map_4k(0x200000, 0x200000);
    mmap.map_4k(0x40000000, 0x40000000);
    mmap.map_4k(0x1000000000, 0x1000000000);
    mmap.map_4k(0x200000000000, 0x200000000000);
    mmap.map_4k(0x40000000000000, 0x40000000000000);
    mmap.release(0x1000);
    mmap.release(0x200000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 1g release range")
{
    ept::mmap mmap{};
    mmap.map_1g(0x40000000, 0x40000000);
    mmap.map_1g(0x80000000, 0x80000000);
    mmap.map_1g(0xC0000000, 0xC0000000);
    mmap.release(0x40000000);
    mmap.release(0x80000000);
    mmap.release(0xC0000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 2m release range")
{
    ept::mmap mmap{};
    mmap.map_2m(0x200000, 0x200000);
    mmap.map_2m(0x400000, 0x400000);
    mmap.map_2m(0x600000, 0x600000);
    mmap.release(0x200000);
    mmap.release(0x400000);
    mmap.release(0x600000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 4k release range")
{
    ept::mmap mmap{};
    mmap.map_4k(0x1000, 0x1000);
    mmap.map_4k(0x2000, 0x2000);
    mmap.map_4k(0x3000, 0x3000);
    mmap.release(0x1000);
    mmap.release(0x2000);
    mmap.release(0x3000);
    CHECK(g_allocated_pages.size() == 1);
}
