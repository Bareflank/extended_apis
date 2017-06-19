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

    void test_resume();
    void test_resume_and_advance();
    void test_handle_exit_invalid();
    void test_handle_exit_monitor_trap_flag();
    void test_handle_exit_io_instruction();
    void test_handle_exit_rdmsr();
    void test_handle_exit_wrmsr();
    void test_register_monitor_trap();
    void test_clear_monitor_trap_by_default();
    void test_log_io_access_enabled();
    void test_log_io_access_disabled();
    void test_clear_io_access_log();
    void test_handle_vmcall_overrun_denials_buffer();

    void test_handle_vmcall_registers_unknown();
    void test_handle_vmcall_registers_io_instruction_unknown();
    void test_handle_vmcall_registers_io_instruction_enable_io_bitmaps_allowed();
    void test_handle_vmcall_registers_io_instruction_enable_io_bitmaps_logged();
    void test_handle_vmcall_registers_io_instruction_enable_io_bitmaps_denied();
    void test_handle_vmcall_registers_io_instruction_disable_io_bitmaps_allowed();
    void test_handle_vmcall_registers_io_instruction_disable_io_bitmaps_logged();
    void test_handle_vmcall_registers_io_instruction_disable_io_bitmaps_denied();
    void test_handle_vmcall_registers_io_instruction_trap_on_io_access_allowed();
    void test_handle_vmcall_registers_io_instruction_trap_on_io_access_logged();
    void test_handle_vmcall_registers_io_instruction_trap_on_io_access_denied();
    void test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_allowed();
    void test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_logged();
    void test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_denied();
    void test_handle_vmcall_registers_io_instruction_pass_through_io_access_allowed();
    void test_handle_vmcall_registers_io_instruction_pass_through_io_access_logged();
    void test_handle_vmcall_registers_io_instruction_pass_through_io_access_denied();
    void test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_allowed();
    void test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_logged();
    void test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_denied();
    void test_handle_vmcall_registers_vpid_unknown();
    void test_handle_vmcall_registers_vpid_enable_vpid_allowed();
    void test_handle_vmcall_registers_vpid_enable_vpid_logged();
    void test_handle_vmcall_registers_vpid_enable_vpid_denied();
    void test_handle_vmcall_registers_vpid_disable_vpid_allowed();
    void test_handle_vmcall_registers_vpid_disable_vpid_logged();
    void test_handle_vmcall_registers_vpid_disable_vpid_denied();
    void test_handle_vmcall_registers_msr_unknown();
    void test_handle_vmcall_registers_msr_enable_msr_bitmap_allowed();
    void test_handle_vmcall_registers_msr_enable_msr_bitmap_logged();
    void test_handle_vmcall_registers_msr_enable_msr_bitmap_denied();
    void test_handle_vmcall_registers_msr_disable_msr_bitmap_allowed();
    void test_handle_vmcall_registers_msr_disable_msr_bitmap_logged();
    void test_handle_vmcall_registers_msr_disable_msr_bitmap_denied();
    void test_handle_vmcall_registers_rdmsr_unknown();
    void test_handle_vmcall_registers_rdmsr_trap_on_rdmsr_access_allowed();
    void test_handle_vmcall_registers_rdmsr_trap_on_rdmsr_access_logged();
    void test_handle_vmcall_registers_rdmsr_trap_on_rdmsr_access_denied();
    void test_handle_vmcall_registers_rdmsr_trap_on_all_rdmsr_accesses_allowed();
    void test_handle_vmcall_registers_rdmsr_trap_on_all_rdmsr_accesses_logged();
    void test_handle_vmcall_registers_rdmsr_trap_on_all_rdmsr_accesses_denied();
    void test_handle_vmcall_registers_rdmsr_pass_through_rdmsr_access_allowed();
    void test_handle_vmcall_registers_rdmsr_pass_through_rdmsr_access_logged();
    void test_handle_vmcall_registers_rdmsr_pass_through_rdmsr_access_denied();
    void test_handle_vmcall_registers_rdmsr_pass_through_all_rdmsr_accesses_allowed();
    void test_handle_vmcall_registers_rdmsr_pass_through_all_rdmsr_accesses_logged();
    void test_handle_vmcall_registers_rdmsr_pass_through_all_rdmsr_accesses_denied();
    void test_handle_vmcall_registers_wrmsr_unknown();
    void test_handle_vmcall_registers_wrmsr_trap_on_wrmsr_access_allowed();
    void test_handle_vmcall_registers_wrmsr_trap_on_wrmsr_access_logged();
    void test_handle_vmcall_registers_wrmsr_trap_on_wrmsr_access_denied();
    void test_handle_vmcall_registers_wrmsr_trap_on_all_wrmsr_accesses_allowed();
    void test_handle_vmcall_registers_wrmsr_trap_on_all_wrmsr_accesses_logged();
    void test_handle_vmcall_registers_wrmsr_trap_on_all_wrmsr_accesses_denied();
    void test_handle_vmcall_registers_wrmsr_pass_through_wrmsr_access_allowed();
    void test_handle_vmcall_registers_wrmsr_pass_through_wrmsr_access_logged();
    void test_handle_vmcall_registers_wrmsr_pass_through_wrmsr_access_denied();
    void test_handle_vmcall_registers_wrmsr_pass_through_all_wrmsr_accesses_allowed();
    void test_handle_vmcall_registers_wrmsr_pass_through_all_wrmsr_accesses_logged();
    void test_handle_vmcall_registers_wrmsr_pass_through_all_wrmsr_accesses_denied();

    void test_handle_vmcall_json_unknown();
    void test_handle_vmcall_json_verifiers_clear_denials_allowed();
    void test_handle_vmcall_json_verifiers_clear_denials_logged();
    void test_handle_vmcall_json_verifiers_clear_denials_denied();
    void test_handle_vmcall_json_verifiers_dump_policy_allowed();
    void test_handle_vmcall_json_verifiers_dump_policy_logged();
    void test_handle_vmcall_json_verifiers_dump_policy_denied();
    void test_handle_vmcall_json_verifiers_dump_denials_allowed();
    void test_handle_vmcall_json_verifiers_dump_denials_logged();
    void test_handle_vmcall_json_verifiers_dump_denials_denied();
    void test_handle_vmcall_json_io_instruction_enable_io_bitmaps_missing_enabled();
    void test_handle_vmcall_json_io_instruction_enable_io_bitmaps_invalid_enabled();
    void test_handle_vmcall_json_io_instruction_enable_io_bitmaps_allowed();
    void test_handle_vmcall_json_io_instruction_enable_io_bitmaps_logged();
    void test_handle_vmcall_json_io_instruction_enable_io_bitmaps_denied();
    void test_handle_vmcall_json_io_instruction_trap_on_io_access_missing_port();
    void test_handle_vmcall_json_io_instruction_trap_on_io_access_invalid_port();
    void test_handle_vmcall_json_io_instruction_trap_on_io_access_allowed();
    void test_handle_vmcall_json_io_instruction_trap_on_io_access_logged();
    void test_handle_vmcall_json_io_instruction_trap_on_io_access_denied();
    void test_handle_vmcall_json_io_instruction_pass_through_io_access_missing_port();
    void test_handle_vmcall_json_io_instruction_pass_through_io_access_invalid_port();
    void test_handle_vmcall_json_io_instruction_pass_through_io_access_allowed();
    void test_handle_vmcall_json_io_instruction_pass_through_io_access_logged();
    void test_handle_vmcall_json_io_instruction_pass_through_io_access_denied();
    void test_handle_vmcall_json_io_instruction_whitelist_io_access_missing_ports();
    void test_handle_vmcall_json_io_instruction_whitelist_io_access_invalid_ports();
    void test_handle_vmcall_json_io_instruction_whitelist_io_access_allowed();
    void test_handle_vmcall_json_io_instruction_whitelist_io_access_logged();
    void test_handle_vmcall_json_io_instruction_whitelist_io_access_denied();
    void test_handle_vmcall_json_io_instruction_blacklist_io_access_missing_ports();
    void test_handle_vmcall_json_io_instruction_blacklist_io_access_invalid_ports();
    void test_handle_vmcall_json_io_instruction_blacklist_io_access_allowed();
    void test_handle_vmcall_json_io_instruction_blacklist_io_access_logged();
    void test_handle_vmcall_json_io_instruction_blacklist_io_access_denied();
    void test_handle_vmcall_json_io_instruction_log_io_access_missing_enabled();
    void test_handle_vmcall_json_io_instruction_log_io_access_invalid_enabled();
    void test_handle_vmcall_json_io_instruction_log_io_access_allowed();
    void test_handle_vmcall_json_io_instruction_log_io_access_logged();
    void test_handle_vmcall_json_io_instruction_log_io_access_denied();
    void test_handle_vmcall_json_io_instruction_clear_io_access_log_allowed();
    void test_handle_vmcall_json_io_instruction_clear_io_access_log_logged();
    void test_handle_vmcall_json_io_instruction_clear_io_access_log_denied();
    void test_handle_vmcall_json_io_instruction_io_access_log_allowed();
    void test_handle_vmcall_json_io_instruction_io_access_log_logged();
    void test_handle_vmcall_json_io_instruction_io_access_log_denied();
    void test_handle_vmcall_json_vpid_enable_vpid_missing_enabled();
    void test_handle_vmcall_json_vpid_enable_vpid_invalid_enabled();
    void test_handle_vmcall_json_vpid_enable_vpid_allowed();
    void test_handle_vmcall_json_vpid_enable_vpid_logged();
    void test_handle_vmcall_json_vpid_enable_vpid_denied();
    void test_handle_vmcall_json_msr_enable_msr_bitmap_missing_enabled();
    void test_handle_vmcall_json_msr_enable_msr_bitmap_invalid_enabled();
    void test_handle_vmcall_json_msr_enable_msr_bitmap_allowed();
    void test_handle_vmcall_json_msr_enable_msr_bitmap_logged();
    void test_handle_vmcall_json_msr_enable_msr_bitmap_denied();
    void test_handle_vmcall_json_rdmsr_trap_on_rdmsr_access_missing_msr();
    void test_handle_vmcall_json_rdmsr_trap_on_rdmsr_access_invalid_msr();
    void test_handle_vmcall_json_rdmsr_trap_on_rdmsr_access_allowed();
    void test_handle_vmcall_json_rdmsr_trap_on_rdmsr_access_logged();
    void test_handle_vmcall_json_rdmsr_trap_on_rdmsr_access_denied();
    void test_handle_vmcall_json_rdmsr_pass_through_rdmsr_access_missing_rdmsr();
    void test_handle_vmcall_json_rdmsr_pass_through_rdmsr_access_invalid_msr();
    void test_handle_vmcall_json_rdmsr_pass_through_rdmsr_access_allowed();
    void test_handle_vmcall_json_rdmsr_pass_through_rdmsr_access_logged();
    void test_handle_vmcall_json_rdmsr_pass_through_rdmsr_access_denied();
    void test_handle_vmcall_json_rdmsr_whitelist_rdmsr_access_missing_rdmsrs();
    void test_handle_vmcall_json_rdmsr_whitelist_rdmsr_access_invalid_msrs();
    void test_handle_vmcall_json_rdmsr_whitelist_rdmsr_access_allowed();
    void test_handle_vmcall_json_rdmsr_whitelist_rdmsr_access_logged();
    void test_handle_vmcall_json_rdmsr_whitelist_rdmsr_access_denied();
    void test_handle_vmcall_json_rdmsr_blacklist_rdmsr_access_missing_rdmsrs();
    void test_handle_vmcall_json_rdmsr_blacklist_rdmsr_access_invalid_msrs();
    void test_handle_vmcall_json_rdmsr_blacklist_rdmsr_access_allowed();
    void test_handle_vmcall_json_rdmsr_blacklist_rdmsr_access_logged();
    void test_handle_vmcall_json_rdmsr_blacklist_rdmsr_access_denied();
    void test_handle_vmcall_json_rdmsr_log_rdmsr_access_missing_enabled();
    void test_handle_vmcall_json_rdmsr_log_rdmsr_access_invalid_enabled();
    void test_handle_vmcall_json_rdmsr_log_rdmsr_access_allowed();
    void test_handle_vmcall_json_rdmsr_log_rdmsr_access_logged();
    void test_handle_vmcall_json_rdmsr_log_rdmsr_access_denied();
    void test_handle_vmcall_json_rdmsr_clear_rdmsr_access_log_allowed();
    void test_handle_vmcall_json_rdmsr_clear_rdmsr_access_log_logged();
    void test_handle_vmcall_json_rdmsr_clear_rdmsr_access_log_denied();
    void test_handle_vmcall_json_rdmsr_rdmsr_access_log_allowed();
    void test_handle_vmcall_json_rdmsr_rdmsr_access_log_logged();
    void test_handle_vmcall_json_rdmsr_rdmsr_access_log_denied();
    void test_handle_vmcall_json_wrmsr_trap_on_wrmsr_access_missing_msr();
    void test_handle_vmcall_json_wrmsr_trap_on_wrmsr_access_invalid_msr();
    void test_handle_vmcall_json_wrmsr_trap_on_wrmsr_access_allowed();
    void test_handle_vmcall_json_wrmsr_trap_on_wrmsr_access_logged();
    void test_handle_vmcall_json_wrmsr_trap_on_wrmsr_access_denied();
    void test_handle_vmcall_json_wrmsr_pass_through_wrmsr_access_missing_wrmsr();
    void test_handle_vmcall_json_wrmsr_pass_through_wrmsr_access_invalid_msr();
    void test_handle_vmcall_json_wrmsr_pass_through_wrmsr_access_allowed();
    void test_handle_vmcall_json_wrmsr_pass_through_wrmsr_access_logged();
    void test_handle_vmcall_json_wrmsr_pass_through_wrmsr_access_denied();
    void test_handle_vmcall_json_wrmsr_whitelist_wrmsr_access_missing_wrmsrs();
    void test_handle_vmcall_json_wrmsr_whitelist_wrmsr_access_invalid_msrs();
    void test_handle_vmcall_json_wrmsr_whitelist_wrmsr_access_allowed();
    void test_handle_vmcall_json_wrmsr_whitelist_wrmsr_access_logged();
    void test_handle_vmcall_json_wrmsr_whitelist_wrmsr_access_denied();
    void test_handle_vmcall_json_wrmsr_blacklist_wrmsr_access_missing_wrmsrs();
    void test_handle_vmcall_json_wrmsr_blacklist_wrmsr_access_invalid_msrs();
    void test_handle_vmcall_json_wrmsr_blacklist_wrmsr_access_allowed();
    void test_handle_vmcall_json_wrmsr_blacklist_wrmsr_access_logged();
    void test_handle_vmcall_json_wrmsr_blacklist_wrmsr_access_denied();
    void test_handle_vmcall_json_wrmsr_log_wrmsr_access_missing_enabled();
    void test_handle_vmcall_json_wrmsr_log_wrmsr_access_invalid_enabled();
    void test_handle_vmcall_json_wrmsr_log_wrmsr_access_allowed();
    void test_handle_vmcall_json_wrmsr_log_wrmsr_access_logged();
    void test_handle_vmcall_json_wrmsr_log_wrmsr_access_denied();
    void test_handle_vmcall_json_wrmsr_clear_wrmsr_access_log_allowed();
    void test_handle_vmcall_json_wrmsr_clear_wrmsr_access_log_logged();
    void test_handle_vmcall_json_wrmsr_clear_wrmsr_access_log_denied();
    void test_handle_vmcall_json_wrmsr_wrmsr_access_log_allowed();
    void test_handle_vmcall_json_wrmsr_wrmsr_access_log_logged();
    void test_handle_vmcall_json_wrmsr_wrmsr_access_log_denied();

    void test_handle_exit__ctl_reg_access();
    void test_set_gpr_value_by_index_reg();
    void test_get_gpr_value_by_index_reg();
};

#endif
