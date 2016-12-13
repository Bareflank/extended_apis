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

#include <gsl/gsl>

#include <test.h>
#include <vmcs/ept_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

bool virt_to_phys_return_nullptr = false;
constexpr ept_intel_x64::integer_pointer virt = 0x0000123456780000UL;

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x0000000ABCDEF0000);

    return mm;
}

void
eapis_ut::test_ept_intel_x64_no_entry()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&pt = std::make_unique<ept_intel_x64>();

        this->expect_true(pt->phys_addr() != 0);
        this->expect_true(pt->read_access());
        this->expect_true(pt->write_access());
        this->expect_true(pt->execute_access());
        this->expect_true(pt->memory_type() == 0);
        this->expect_false(pt->ignore_pat());
        this->expect_false(pt->entry_type());
        this->expect_false(pt->accessed());
        this->expect_false(pt->dirty());
        this->expect_false(pt->execute_access_user());
        this->expect_false(pt->suppress_ve());
    });
}

void
eapis_ut::test_ept_intel_x64_with_entry()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ept_intel_x64::integer_pointer entry = 0;
        auto &&pt = std::make_unique<ept_intel_x64>(&entry);

        this->expect_true(pt->phys_addr() != 0);
        this->expect_true(pt->read_access());
        this->expect_true(pt->write_access());
        this->expect_true(pt->execute_access());
        this->expect_true(pt->memory_type() == 0);
        this->expect_false(pt->ignore_pat());
        this->expect_false(pt->entry_type());
        this->expect_false(pt->accessed());
        this->expect_false(pt->dirty());
        this->expect_false(pt->execute_access_user());
        this->expect_false(pt->suppress_ve());
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_1g_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();

        eptp->add_page_1g(virt);
        this->expect_true(eptp->global_size() == 2);

        eptp->add_page_1g(virt + 0x40000000);
        this->expect_true(eptp->global_size() == 3);

        eptp->add_page_1g(virt + 0x40000000000);
        this->expect_true(eptp->global_size() == 5);

        this->expect_no_exception([&]{ eptp->find_epte(virt); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x1000); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x40000000); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x40000000000); });
        this->expect_exception([&]{ eptp->find_epte(virt + 0x80000000000); }, ""_ut_ree);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 4);

        eptp->remove_page(virt + 0x40000000);
        this->expect_true(eptp->global_size() == 2);

        eptp->remove_page(virt + 0x40000000000);
        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_2m_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();

        eptp->add_page_2m(virt);
        this->expect_true(eptp->global_size() == 3);

        eptp->add_page_2m(virt + 0x200000);
        this->expect_true(eptp->global_size() == 4);

        eptp->add_page_2m(virt + 0x20000000);
        this->expect_true(eptp->global_size() == 5);

        this->expect_no_exception([&]{ eptp->find_epte(virt); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x1000); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x200000); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x20000000); });
        this->expect_exception([&]{ eptp->find_epte(virt + 0x80000000000); }, ""_ut_ree);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 4);

        eptp->remove_page(virt + 0x200000);
        this->expect_true(eptp->global_size() == 3);

        eptp->remove_page(virt + 0x20000000);
        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_add_remove_page_4k_success()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();

        eptp->add_page_4k(virt);
        this->expect_true(eptp->global_size() == 4);

        eptp->add_page_4k(virt + 0x1000);
        this->expect_true(eptp->global_size() == 5);

        eptp->add_page_4k(virt + 0x1000000);
        this->expect_true(eptp->global_size() == 7);

        this->expect_no_exception([&]{ eptp->find_epte(virt); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x1000); });
        this->expect_no_exception([&]{ eptp->find_epte(virt + 0x1000000); });
        this->expect_exception([&]{ eptp->find_epte(virt + 0x80000000000); }, ""_ut_ree);

        eptp->remove_page(virt);
        this->expect_true(eptp->global_size() == 6);

        eptp->remove_page(virt + 0x1000);
        this->expect_true(eptp->global_size() == 4);

        eptp->remove_page(virt + 0x1000000);
        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_add_page_twice_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();

        eptp->add_page_4k(virt);
        this->expect_exception([&]{ eptp->add_page_4k(virt); }, ""_ut_ree);
    });
}

void
eapis_ut::test_ept_intel_x64_remove_page_twice_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();

        eptp->add_page_4k(virt);
        eptp->add_page_4k(virt + 0x1000);

        eptp->remove_page(virt);
        this->expect_exception([&]{ eptp->remove_page(virt); }, ""_ut_ree);
        eptp->remove_page(virt + 0x1000);

        this->expect_true(eptp->global_size() == 0);
    });
}

void
eapis_ut::test_ept_intel_x64_remove_page_unknown_failure()
{
    MockRepository mocks;
    setup_mm(mocks);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto &&eptp = std::make_unique<ept_intel_x64>();
        this->expect_exception([&]{ eptp->remove_page(virt); }, ""_ut_ree);
    });
}
