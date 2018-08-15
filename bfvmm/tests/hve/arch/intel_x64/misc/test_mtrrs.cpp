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

#include <test/support.h>
#include <hve/arch/intel_x64/misc/mtrrs.h>

using range_t = mtrrs::range_t;

TEST_CASE("disable mtrrs")
{
    ::x64::msrs::ia32_mtrrcap::vcnt::set(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::mtrr_enable::disable();

    mtrrs m{};
    CHECK(m.size() == 1);
}

TEST_CASE("disable mtrrs with corrupt set up")
{
    ::x64::msrs::ia32_mtrrcap::vcnt::set(42);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(6);
    ::intel_x64::msrs::ia32_mtrr_def_type::mtrr_enable::disable();

    mtrrs m{};
    CHECK(m.size() == 1);
}

TEST_CASE("no variable ranges")
{
    enable_mtrrs(0);

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0xFFFFFFFFFFFFFFFF - 0x100000});
}

TEST_CASE("1 variable ranges")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{wb, 0x100000, 0x100000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0xFFFFFFFFFFFFFFFF - 0x200000});
}

TEST_CASE("out-of-order variable ranges")
{
    enable_mtrrs(2);
    add_variable_range(0, range_t{wb, 0x200000, 0x100000});
    add_variable_range(1, range_t{wb, 0x100000, 0x100000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0x100000});
    CHECK(m.ranges().at(3) == range_t{wb, 0x300000, 0xFFFFFFFFFFFFFFFF - 0x300000});
}

TEST_CASE("overlapping ranges multiple")
{
    enable_mtrrs(5);
    add_variable_range(0, range_t{wb, 0x100000, 0x400000});
    add_variable_range(1, range_t{wb, 0x100000, 0x100000});
    add_variable_range(2, range_t{wb, 0x200000, 0x100000});
    add_variable_range(3, range_t{wb, 0x300000, 0x100000});
    add_variable_range(4, range_t{wb, 0x400000, 0x100000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0x100000});
    CHECK(m.ranges().at(3) == range_t{wb, 0x300000, 0x100000});
    CHECK(m.ranges().at(4) == range_t{wb, 0x400000, 0x100000});
    CHECK(m.ranges().at(5) == range_t{wb, 0x500000, 0xFFFFFFFFFFFFFFFF - 0x500000});
}

TEST_CASE("overlapping ranges, one disabled")
{
    enable_mtrrs(5);
    add_variable_range(0, range_t{wb, 0x100000, 0x400000});
    add_variable_range(1, range_t{wb, 0x100000, 0x100000});
    add_variable_range(2, range_t{uc, 0x200000, 0x100000}, true);
    add_variable_range(3, range_t{wb, 0x300000, 0x100000});
    add_variable_range(4, range_t{wb, 0x400000, 0x100000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0x100000});
    CHECK(m.ranges().at(3) == range_t{wb, 0x300000, 0x100000});
    CHECK(m.ranges().at(4) == range_t{wb, 0x400000, 0x100000});
    CHECK(m.ranges().at(5) == range_t{wb, 0x500000, 0xFFFFFFFFFFFFFFFF - 0x500000});
}

TEST_CASE("overlapping ranges version #2")
{
    enable_mtrrs(2);
    add_variable_range(0, range_t{wb, 0x100000, 0x100000});
    add_variable_range(1, range_t{wb, 0x100000, 0x400000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0x300000});
}

TEST_CASE("overlapping ranges version #3")
{
    enable_mtrrs(2);
    add_variable_range(0, range_t{wb, 0x400000, 0x100000});
    add_variable_range(1, range_t{wb, 0x100000, 0x400000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x300000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x400000, 0x100000});
}

TEST_CASE("overlapping ranges version #4")
{
    enable_mtrrs(2);
    add_variable_range(0, range_t{wb, 0x200000, 0x100000});
    add_variable_range(1, range_t{wb, 0x100000, 0x400000});

    mtrrs m{};

    CHECK(m.ranges().at(0) == range_t{uc, 0, 0x100000});
    CHECK(m.ranges().at(1) == range_t{wb, 0x100000, 0x100000});
    CHECK(m.ranges().at(2) == range_t{wb, 0x200000, 0x100000});
    CHECK(m.ranges().at(3) == range_t{wb, 0x300000, 0x200000});
}

TEST_CASE("invalid overlapping ranges version")
{
    enable_mtrrs(5);
    add_variable_range(0, range_t{wb, 0x100000, 0x200000});
    add_variable_range(1, range_t{wb, 0x200000, 0x200000});

    mtrrs m{};
    CHECK(m.size() == 0);
}

TEST_CASE("default type: write_back")
{
    enable_mtrrs(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(
        ::intel_x64::msrs::ia32_mtrr_def_type::type::write_back
    );

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_back,
        0x100000,
        0xFFFFFFFFFFFFFFFF - 0x100000
    });
}

TEST_CASE("default type: write_protected")
{
    enable_mtrrs(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(
        ::intel_x64::msrs::ia32_mtrr_def_type::type::write_protected
    );

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_protected,
        0x100000,
        0xFFFFFFFFFFFFFFFF - 0x100000
    });
}

TEST_CASE("default type: write_through")
{
    enable_mtrrs(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(
        ::intel_x64::msrs::ia32_mtrr_def_type::type::write_through
    );

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_through,
        0x100000,
        0xFFFFFFFFFFFFFFFF - 0x100000
    });
}

TEST_CASE("default type: write_combining")
{
    enable_mtrrs(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(
        ::intel_x64::msrs::ia32_mtrr_def_type::type::write_combining
    );

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_combining,
        0x100000,
        0xFFFFFFFFFFFFFFFF - 0x100000
    });
}

TEST_CASE("default type: uncacheable")
{
    enable_mtrrs(0);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(
        ::intel_x64::msrs::ia32_mtrr_def_type::type::uncacheable
    );

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::uncacheable,
        0x100000,
        0xFFFFFFFFFFFFFFFF - 0x100000
    });
}

TEST_CASE("variable range type: write_back")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{
        ept::mmap::memory_type::write_back,
        0x100000,
        0x100000
    });

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_back,
        0x100000,
        0x100000
    });
}

TEST_CASE("variable range type: write_protected")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{
        ept::mmap::memory_type::write_protected,
        0x100000,
        0x100000
    });

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_protected,
        0x100000,
        0x100000
    });
}

TEST_CASE("variable range type: write_through")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{
        ept::mmap::memory_type::write_through,
        0x100000,
        0x100000
    });

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_through,
        0x100000,
        0x100000
    });
}

TEST_CASE("variable range type: write_combining")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{
        ept::mmap::memory_type::write_combining,
        0x100000,
        0x100000
    });

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::write_combining,
        0x100000,
        0x100000
    });
}

TEST_CASE("variable range type: uncacheable")
{
    enable_mtrrs(1);
    add_variable_range(0, range_t{
        ept::mmap::memory_type::uncacheable,
        0x100000,
        0x100000
    });

    mtrrs m{};

    CHECK(m.ranges().at(1) == range_t{
        ept::mmap::memory_type::uncacheable,
        0x100000,
        0x100000
    });
}
