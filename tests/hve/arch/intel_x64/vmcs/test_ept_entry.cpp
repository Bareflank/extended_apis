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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

#include <util/bitmanip.h>
#include "../../../../../include/support/arch/intel_x64/test_support.h"
#include "../../../../../include/hve/arch/intel_x64/vmcs/ept_entry.h"

namespace intel = eapis::hve::intel_x64;

using epte_type = intel::ept_entry::integer_pointer;

TEST_CASE("ept_entry: read access")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_read_access(true);
    CHECK(epte->read_access());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 0));

    epte->set_read_access(false);
    CHECK(!epte->read_access());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: write access")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_write_access(true);
    CHECK(epte->write_access());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 1));

    epte->set_write_access(false);
    CHECK(!epte->write_access());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: execute access")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_execute_access(true);
    CHECK(epte->execute_access());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 2));

    epte->set_execute_access(false);
    CHECK(!epte->execute_access());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: memory type")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_memory_type(6UL);
    CHECK(epte->read_access());
    CHECK(epte->write_access());
    CHECK(epte->memory_type() == 6UL);

    epte->set_memory_type(0x1004);
    CHECK(epte->memory_type() == 4UL);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_memory_type(0x0);
    CHECK(epte->read_access());
    CHECK(epte->write_access());
    CHECK(epte->memory_type() == 0x0);
}

TEST_CASE("ept_entry: ignore pat")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_ignore_pat(true);
    CHECK(epte->ignore_pat());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 6));

    epte->set_ignore_pat(false);
    CHECK(!epte->ignore_pat());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: entry type")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_entry_type(true);
    CHECK(epte->entry_type());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 7));

    epte->set_entry_type(false);
    CHECK(!epte->entry_type());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: accessed")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_accessed(true);
    CHECK(epte->accessed());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 8));

    epte->set_accessed(false);
    CHECK(!epte->accessed());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: dirty")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_dirty(true);
    CHECK(epte->dirty());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 9));

    epte->set_dirty(false);
    CHECK(!epte->dirty());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: execute access user")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_execute_access_user(true);
    CHECK(epte->execute_access_user());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 10));

    epte->set_execute_access_user(false);
    CHECK(!epte->execute_access_user());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: physical address")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_phys_addr(0x0000ABCDEF123000);
    CHECK(epte->read_access());
    CHECK(epte->write_access());
    CHECK(epte->phys_addr() == 0x0000ABCDEF123000);

    epte->set_phys_addr(0x0000ABCDEF123010);
    CHECK(epte->phys_addr() == 0x0000ABCDEF123000);

    epte->set_read_access(true);
    epte->set_write_access(true);
    epte->set_phys_addr(0x0);
    CHECK(epte->read_access());
    CHECK(epte->write_access());
    CHECK(epte->phys_addr() == 0x0);
}

TEST_CASE("ept_entry: suppress ve")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->set_suppress_ve(true);
    CHECK(epte->suppress_ve());
    CHECK(num_bits_set(entry) == 1);
    CHECK(is_bit_set(entry, 63));

    epte->set_suppress_ve(false);
    CHECK(!epte->suppress_ve());
    CHECK(num_bits_set(entry) == 0);
}

TEST_CASE("ept_entry: trap on access")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->trap_on_access();
    CHECK(!epte->read_access());
    CHECK(!epte->write_access());
    CHECK(!epte->execute_access());
}

TEST_CASE("ept_entry: pass through access")
{
    epte_type entry = 0;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->pass_through_access();
    CHECK(epte->read_access());
    CHECK(epte->write_access());
    CHECK(epte->execute_access());
}

TEST_CASE("ept_entry: clear")
{
    epte_type entry = 0xFFFFFFFFFFFFFFFF;
    auto epte = std::make_unique<intel::ept_entry>(&entry);

    epte->clear();
    CHECK(entry == 0);
}

#endif
