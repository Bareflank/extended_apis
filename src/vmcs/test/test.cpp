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

eapis_ut::eapis_ut()
{
}

bool
eapis_ut::init()
{
    return true;
}

bool
eapis_ut::fini()
{
    return true;
}

bool
eapis_ut::list()
{
    this->test_construction();
    this->test_launch();
    this->test_enable_vpid();
    this->test_disable_vpid();
    this->test_trap_on_io_access();
    this->test_trap_on_all_io_accesses();
    this->test_pass_through_io_access();
    this->test_pass_through_all_io_accesses();
    this->test_whitelist_io_access();
    this->test_blacklist_io_access();


    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(eapis_ut);
}
