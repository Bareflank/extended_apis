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

#include <bitmanip.h>
#include <vmcs/ept_entry_intel_x64.h>

using epte_type = ept_entry_intel_x64::integer_pointer;

void
eapis_ut::test_ept_entry_intel_x64_invalid()
{
    std::make_unique<ept_entry_intel_x64>();
}

void
eapis_ut::test_ept_entry_intel_x64_read_access()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_read_access(true);
    this->expect_true(epte->read_access());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 0));

    epte->set_read_access(false);
    this->expect_false(epte->read_access());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_write_access()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_write_access(true);
    this->expect_true(epte->write_access());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 1));

    epte->set_write_access(false);
    this->expect_false(epte->write_access());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_execute_access()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_execute_access(true);
    this->expect_true(epte->execute_access());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 2));

    epte->set_execute_access(false);
    this->expect_false(epte->execute_access());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_memory_type()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_memory_type(6UL);
    this->expect_true(epte->read_access());
    this->expect_true(epte->write_access());
    this->expect_true(epte->memory_type() == 6UL);

    epte->set_memory_type(0x1004);
    this->expect_true(epte->memory_type() == 4UL);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_memory_type(0x0);
    this->expect_true(epte->read_access());
    this->expect_true(epte->write_access());
    this->expect_true(epte->memory_type() == 0x0);
}

void
eapis_ut::test_ept_entry_intel_x64_ignore_pat()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_ignore_pat(true);
    this->expect_true(epte->ignore_pat());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 6));

    epte->set_ignore_pat(false);
    this->expect_false(epte->ignore_pat());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_entry_type()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_entry_type(true);
    this->expect_true(epte->entry_type());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 7));

    epte->set_entry_type(false);
    this->expect_false(epte->entry_type());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_accessed()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_accessed(true);
    this->expect_true(epte->accessed());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 8));

    epte->set_accessed(false);
    this->expect_false(epte->accessed());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_dirty()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_dirty(true);
    this->expect_true(epte->dirty());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 9));

    epte->set_dirty(false);
    this->expect_false(epte->dirty());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_execute_access_user()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_execute_access_user(true);
    this->expect_true(epte->execute_access_user());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 10));

    epte->set_execute_access_user(false);
    this->expect_false(epte->execute_access_user());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_phys_addr()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_phys_addr(0x0000ABCDEF123000);
    this->expect_true(epte->read_access());
    this->expect_true(epte->write_access());
    this->expect_true(epte->phys_addr() == 0x0000ABCDEF123000);

    epte->set_phys_addr(0x0000ABCDEF123010);
    this->expect_true(epte->phys_addr() == 0x0000ABCDEF123000);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_phys_addr(0x0);
    this->expect_true(epte->read_access());
    this->expect_true(epte->write_access());
    this->expect_true(epte->phys_addr() == 0x0);
}

void
eapis_ut::test_ept_entry_intel_x64_suppress_ve()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->set_suppress_ve(true);
    this->expect_true(epte->suppress_ve());
    this->expect_true(num_bits_set(entry) == 1);
    this->expect_true(is_bit_set(entry, 63));

    epte->set_suppress_ve(false);
    this->expect_false(epte->suppress_ve());
    this->expect_true(num_bits_set(entry) == 0);
}

void
eapis_ut::test_ept_entry_intel_x64_trap_on_access()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->trap_on_access();
    this->expect_false(epte->read_access());
    this->expect_false(epte->write_access());
    this->expect_false(epte->execute_access());
}

void
eapis_ut::test_ept_entry_intel_x64_pass_through_access()
{
    epte_type entry = 0;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->pass_through_access();
    this->expect_true(epte->read_access());
    this->expect_true(epte->write_access());
    this->expect_true(epte->execute_access());
}

void
eapis_ut::test_ept_entry_intel_x64_clear()
{
    epte_type entry = 0xFFFFFFFFFFFFFFFF;
    auto &&epte = std::make_unique<ept_entry_intel_x64>(&entry);

    epte->clear();
    this->expect_true(entry == 0);
}
