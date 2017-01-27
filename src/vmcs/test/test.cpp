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
    this->test_enable_ept();
    this->test_disable_ept();
    this->test_set_eptp();

    this->test_ept_entry_intel_x64_read_access();
    this->test_ept_entry_intel_x64_write_access();
    this->test_ept_entry_intel_x64_execute_access();
    this->test_ept_entry_intel_x64_memory_type();
    this->test_ept_entry_intel_x64_ignore_pat();
    this->test_ept_entry_intel_x64_entry_type();
    this->test_ept_entry_intel_x64_accessed();
    this->test_ept_entry_intel_x64_dirty();
    this->test_ept_entry_intel_x64_execute_access_user();
    this->test_ept_entry_intel_x64_phys_addr();
    this->test_ept_entry_intel_x64_suppress_ve();
    this->test_ept_entry_intel_x64_trap_on_access();
    this->test_ept_entry_intel_x64_pass_through_access();
    this->test_ept_entry_intel_x64_clear();

    this->test_ept_intel_x64_add_remove_page_success_without_setting();
    this->test_ept_intel_x64_add_remove_page_1g_success();
    this->test_ept_intel_x64_add_remove_page_2m_success();
    this->test_ept_intel_x64_add_remove_page_4k_success();
    this->test_ept_intel_x64_add_remove_page_swap_success();
    this->test_ept_intel_x64_add_page_twice_success();
    this->test_ept_intel_x64_remove_page_twice_success();
    this->test_ept_intel_x64_remove_page_unknown_success();
    this->test_ept_intel_x64_gpa_to_epte_invalid();
    this->test_ept_intel_x64_gpa_to_epte_success();
    this->test_ept_intel_x64_ept_to_mdl_success();

    this->test_root_ept_intel_x64_eptp();
    this->test_root_ept_intel_x64_map_1g();
    this->test_root_ept_intel_x64_map_2m();
    this->test_root_ept_intel_x64_map_4k();
    this->test_root_ept_intel_x64_map_invalid();
    this->test_root_ept_intel_x64_map_unmap_twice_success();
    this->test_root_ept_intel_x64_setup_identity_map_1g_invalid();
    this->test_root_ept_intel_x64_setup_identity_map_1g_valid();
    this->test_root_ept_intel_x64_setup_identity_map_2m_invalid();
    this->test_root_ept_intel_x64_setup_identity_map_2m_valid();
    this->test_root_ept_intel_x64_setup_identity_map_4k_invalid();
    this->test_root_ept_intel_x64_setup_identity_map_4k_valid();
    this->test_root_page_table_x64_pt_to_mdl();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(eapis_ut);
}
