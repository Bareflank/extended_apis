//
// Bareflank Hypervisor
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

#include <test.h>

#include <vmcs/root_ept_intel_x64.h>
#include <vmcs/ept_entry_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

using namespace intel_x64;

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

void
eapis_ut::test_root_ept_intel_x64_eptp()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_true(root_ept.eptp() == 0x0000000ABCDEF0007);
}

void
eapis_ut::test_root_ept_intel_x64_map_1g()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    // Read / Write
    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Execute Only
    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Trap
    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_1g(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }
}

void
eapis_ut::test_root_ept_intel_x64_map_2m()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    // Read / Write
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Execute Only
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Trap
    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_2m(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }
}

void
eapis_ut::test_root_ept_intel_x64_map_4k()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    // Read / Write
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::rw_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Read / Execute
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::re_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Execute Only
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::eo_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Pass Through
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_true(entry.read_access());
        this->expect_true(entry.write_access());
        this->expect_true(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    // Trap
    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_uc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 0);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wc);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 1);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wt);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 4);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wp);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 5);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }

    {
        root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::tp_wb);
        auto &&entry = root_ept.gpa_to_epte(0x1000UL);
        this->expect_false(entry.read_access());
        this->expect_false(entry.write_access());
        this->expect_false(entry.execute_access());
        this->expect_true(entry.memory_type() == 6);
        root_ept.unmap(0x1000UL);
        this->expect_exception([&] { root_ept.gpa_to_epte(0x1000UL); }, ""_ut_ree);
    }
}

void
eapis_ut::test_root_ept_intel_x64_map_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_exception([&] { root_ept.map_page(0x0, 0x0, 0x0, 0x0); }, ""_ut_lee);
    this->expect_exception([&] { root_ept.map_page(0x0, 0x0, 0x0, ept::pt::size_bytes); }, ""_ut_lee);
}

void
eapis_ut::test_root_ept_intel_x64_map_unmap_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb); });
        this->expect_no_exception([&] { root_ept.map_4k(0x1000UL, 0x1000UL, ept::memory_attr::pt_wb); });
        this->expect_no_exception([&] { root_ept.unmap(0x1000UL); });
        this->expect_no_exception([&] { root_ept.unmap(0x1000UL); });
    });
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_1g_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_exception([&] { root_ept.setup_identity_map_1g(0x1, 0x40000000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.setup_identity_map_1g(0x0, 0x40000001); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_1g(0x1, 0x40000000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_1g(0x0, 0x40000001); }, ""_ut_ffe);
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_1g_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_no_exception([&] { root_ept.setup_identity_map_1g(0x0, 0x40000000); });
    this->expect_no_exception([&] { root_ept.unmap_identity_map_1g(0x0, 0x40000000); });
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_2m_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_exception([&] { root_ept.setup_identity_map_2m(0x1, 0x200000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.setup_identity_map_2m(0x0, 0x200001); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_2m(0x1, 0x200000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_2m(0x0, 0x200001); }, ""_ut_ffe);
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_2m_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_no_exception([&] { root_ept.setup_identity_map_2m(0x0, 0x200000); });
    this->expect_no_exception([&] { root_ept.unmap_identity_map_2m(0x0, 0x200000); });
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_4k_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_exception([&] { root_ept.setup_identity_map_4k(0x1, 0x1000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.setup_identity_map_4k(0x0, 0x1001); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_4k(0x1, 0x1000); }, ""_ut_ffe);
    this->expect_exception([&] { root_ept.unmap_identity_map_4k(0x0, 0x1001); }, ""_ut_ffe);
}

void
eapis_ut::test_root_ept_intel_x64_setup_identity_map_4k_valid()
{
    MockRepository mocks;
    setup_mm(mocks);
    auto &&root_ept = root_ept_intel_x64{};

    this->expect_no_exception([&] { root_ept.setup_identity_map_4k(0x0, 0x1000); });
    this->expect_no_exception([&] { root_ept.unmap_identity_map_4k(0x0, 0x1000); });
}
