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

#include <gsl/gsl>

#include <test.h>
#include <vmcs/ept_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

bool virt_to_phys_return_nullptr = false;
constexpr ept_intel_x64::integer_pointer virt = 0x0000100000000000UL;

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_success_without_setting()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        eptp->add_page_4k(virt);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->add_page_4k(virt + 0x1000);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->add_page_4k(virt + 0x10000);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        eptp->remove_page(virt + 0x1000);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        eptp->remove_page(virt + 0x10000);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_1g_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        auto &&entry1 = eptp->add_page_1g(virt);
        entry1.set_read_access(true);
        this->expect_true(eptp->global_size() == 2);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        auto &&entry2 = eptp->add_page_1g(virt + 0x100);
        entry2.set_read_access(true);
        this->expect_true(eptp->global_size() == 2);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        auto &&entry3 = eptp->add_page_1g(virt + 0x40000000);
        entry3.set_read_access(true);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        auto &&entry4 = eptp->add_page_1g(virt + 0x400000000);
        entry4.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        eptp->remove_page(virt + 0x40000000);
        this->expect_true(eptp->global_size() == 2);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        eptp->remove_page(virt + 0x400000000);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_2m_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        auto &&entry1 = eptp->add_page_2m(virt);
        entry1.set_read_access(true);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        auto &&entry2 = eptp->add_page_2m(virt + 0x100);
        entry2.set_read_access(true);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        auto &&entry3 = eptp->add_page_2m(virt + 0x200000);
        entry3.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        auto &&entry4 = eptp->add_page_2m(virt + 0x2000000);
        entry4.set_read_access(true);
        this->expect_true(eptp->global_size() == 5);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        eptp->remove_page(virt + 0x200000);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        eptp->remove_page(virt + 0x2000000);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_4k_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        auto &&entry1 = eptp->add_page_4k(virt);
        entry1.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        auto &&entry2 = eptp->add_page_4k(virt + 0x100);
        entry2.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        auto &&entry3 = eptp->add_page_4k(virt + 0x1000);
        entry3.set_read_access(true);
        this->expect_true(eptp->global_size() == 5);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        auto &&entry4 = eptp->add_page_4k(virt + 0x10000);
        entry4.set_read_access(true);
        this->expect_true(eptp->global_size() == 6);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 5);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt + 0x1000);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt + 0x10000);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_swap_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        auto &&entry1 = eptp->add_page_4k(virt);
        entry1.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        auto &&entry2 = eptp->add_page_2m(virt);
        entry2.set_read_access(true);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);

        auto &&entry3 = eptp->add_page_4k(virt);
        entry3.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        auto &&entry4 = eptp->add_page_2m(virt);
        entry4.set_read_access(true);
        this->expect_true(eptp->global_size() == 3);
        this->expect_true(eptp->global_capacity() == 512 * 2);

        auto &&entry5 = eptp->add_page_4k(virt);
        entry5.set_read_access(true);
        this->expect_true(eptp->global_size() == 4);
        this->expect_true(eptp->global_capacity() == 512 * 3);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
        this->expect_true(eptp->global_capacity() == 512 * 1);
    });
}

void
eapis_ut::test_ept_intel_x64_add_page_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        eptp->add_page_4k(virt);
        this->expect_no_exception([&]{ eptp->add_page_4k(virt); });
    });
}

void
eapis_ut::test_ept_intel_x64_remove_page_twice_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        eptp->add_page_4k(virt);
        eptp->add_page_4k(virt + 0x1000);

        eptp->remove_page(virt);
        this->expect_no_exception([&]{ eptp->remove_page(virt); });
        eptp->remove_page(virt + 0x1000);

        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_remove_page_unknown_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);
        this->expect_no_exception([&]{ eptp->remove_page(virt); });
    });
}

void
eapis_ut::test_ept_intel_x64_gpa_to_epte_invalid()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        eptp->add_page_4k(virt);

        this->expect_exception([&]{ eptp->gpa_to_epte(virt + 0x40000000); }, ""_ut_ree);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_gpa_to_epte_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&scr3 = 0x0UL;
        auto &&eptp = std::make_unique<ept_intel_x64>(&scr3);

        eptp->add_page_4k(virt);
        this->expect_no_exception([&]{ eptp->gpa_to_epte(virt); });

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 0);
    });
}
