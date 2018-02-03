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

#include "../../../../../include/support/arch/intel_x64/test_support.h"
#include "../../../../../include/hve/arch/intel_x64/vmcs/root_ept.h"
#include "../../../../../include/hve/arch/intel_x64/vmcs/ept_entry.h"

namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;
namespace ept = intel_x64::ept;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("root_ept_intel_x64: eptp")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK(root_ept.eptp() == 0x0000000ABCDEF0007);
}

TEST_CASE("root_ept_intel_x64: map 1g read / write")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 1g read / execute")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 1g read only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::ro_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::ro_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::ro_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::ro_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::ro_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 1g execute only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 1g pass through")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 1g trap")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m read / write")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m read / execute")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m read only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::ro_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::ro_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::ro_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::ro_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::ro_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m execute only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m pass through")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 2m trap")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k read / write")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k read / execute")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k read only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::ro_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::ro_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::ro_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::ro_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::ro_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k execute only")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k pass through")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(entry.read_access());
        CHECK(entry.write_access());
        CHECK(entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map 4k trap")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto entry = root_ept.gpa_to_epte(0x1000UL);
        CHECK(!entry.read_access());
        CHECK(!entry.write_access());
        CHECK(!entry.execute_access());
        CHECK(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        CHECK_THROWS(root_ept.gpa_to_epte(0x1000UL));
    }
}

TEST_CASE("root_ept_intel_x64: map invalid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_THROWS(root_ept.map_page(0x0, 0x0, 0x0, 0x0));
    CHECK_THROWS(root_ept.map_page(0x0, 0x0, 0x0, ept::pt::size_bytes));
}

TEST_CASE("root_ept_intel_x64: map / unmap twice")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_NOTHROW(root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb));
    CHECK_NOTHROW(root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb));
    CHECK_NOTHROW(root_ept.unmap(0x1000UL));
    CHECK_NOTHROW(root_ept.unmap(0x1000UL));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_1g invalid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_THROWS(root_ept.setup_identity_map_1g(0x1, 0x40000000));
    CHECK_THROWS(root_ept.setup_identity_map_1g(0x0, 0x40000001));
    CHECK_THROWS(root_ept.unmap_identity_map_1g(0x1, 0x40000000));
    CHECK_THROWS(root_ept.unmap_identity_map_1g(0x0, 0x40000001));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_1g valid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_NOTHROW(root_ept.setup_identity_map_1g(0x0, 0x40000000));
    CHECK_NOTHROW(root_ept.unmap_identity_map_1g(0x0, 0x40000000));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_2m invalid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_THROWS(root_ept.setup_identity_map_2m(0x1, 0x200000));
    CHECK_THROWS(root_ept.setup_identity_map_2m(0x0, 0x200001));
    CHECK_THROWS(root_ept.unmap_identity_map_2m(0x1, 0x200000));
    CHECK_THROWS(root_ept.unmap_identity_map_2m(0x0, 0x200001));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_2m valid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_NOTHROW(root_ept.setup_identity_map_2m(0x0, 0x200000));
    CHECK_NOTHROW(root_ept.unmap_identity_map_2m(0x0, 0x200000));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_4k invalid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_THROWS(root_ept.setup_identity_map_4k(0x1, 0x1000));
    CHECK_THROWS(root_ept.setup_identity_map_4k(0x0, 0x1001));
    CHECK_THROWS(root_ept.unmap_identity_map_4k(0x1, 0x1000));
    CHECK_THROWS(root_ept.unmap_identity_map_4k(0x0, 0x1001));
}

TEST_CASE("root_ept_intel_x64: setup_identity_map_4k valid")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_NOTHROW(root_ept.setup_identity_map_4k(0x0, 0x1000));
    CHECK_NOTHROW(root_ept.unmap_identity_map_4k(0x0, 0x1000));
}

TEST_CASE("root_ept_intel_x64: ept_to_mdl")
{
    MockRepository mocks;
    setup_mm(mocks);
    root_ept_intel_x64 root_ept{};

    CHECK_NOTHROW(root_ept.ept_to_mdl());
}

#endif
