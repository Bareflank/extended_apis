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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class eapis_ut : public unittest
{
public:

    eapis_ut();
    ~eapis_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_construction();
    void test_launch();
    void test_enable_vpid();
    void test_disable_vpid();
    void test_trap_on_io_access();
    void test_trap_on_all_io_accesses();
    void test_pass_through_io_access();
    void test_pass_through_all_io_accesses();
    void test_whitelist_io_access();
    void test_blacklist_io_access();
    void test_enable_ept();
    void test_disable_ept();
    void test_set_eptp();

    void test_ept_entry_intel_x64_read_access();
    void test_ept_entry_intel_x64_write_access();
    void test_ept_entry_intel_x64_execute_access();
    void test_ept_entry_intel_x64_memory_type();
    void test_ept_entry_intel_x64_ignore_pat();
    void test_ept_entry_intel_x64_entry_type();
    void test_ept_entry_intel_x64_accessed();
    void test_ept_entry_intel_x64_dirty();
    void test_ept_entry_intel_x64_execute_access_user();
    void test_ept_entry_intel_x64_phys_addr();
    void test_ept_entry_intel_x64_suppress_ve();
    void test_ept_entry_intel_x64_trap_on_access();
    void test_ept_entry_intel_x64_pass_through_access();
    void test_ept_entry_intel_x64_clear();

    void test_ept_intel_x64_add_remove_page_success_without_setting();
    void test_ept_intel_x64_add_remove_page_1g_success();
    void test_ept_intel_x64_add_remove_page_2m_success();
    void test_ept_intel_x64_add_remove_page_4k_success();
    void test_ept_intel_x64_add_remove_page_swap_success();
    void test_ept_intel_x64_add_page_twice_success();
    void test_ept_intel_x64_remove_page_twice_success();
    void test_ept_intel_x64_remove_page_unknown_success();
    void test_ept_intel_x64_gpa_to_epte_invalid();
    void test_ept_intel_x64_gpa_to_epte_success();

    void test_root_ept_intel_x64_eptp();
    void test_root_ept_intel_x64_map_1g();
    void test_root_ept_intel_x64_map_2m();
    void test_root_ept_intel_x64_map_4k();
    void test_root_ept_intel_x64_map_invalid();
    void test_root_ept_intel_x64_map_unmap_twice_success();
    void test_root_ept_intel_x64_setup_identity_map_1g_invalid();
    void test_root_ept_intel_x64_setup_identity_map_1g_valid();
    void test_root_ept_intel_x64_setup_identity_map_2m_invalid();
    void test_root_ept_intel_x64_setup_identity_map_2m_valid();
    void test_root_ept_intel_x64_setup_identity_map_4k_invalid();
    void test_root_ept_intel_x64_setup_identity_map_4k_valid();
};

#endif
