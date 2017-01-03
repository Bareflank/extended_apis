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
    this->test_resume();
    this->test_resume_and_advance();
    this->test_handle_exit_invalid();
    this->test_handle_exit_monitor_trap_flag();
    this->test_handle_exit_io_instruction();
    this->test_register_monitor_trap();
    this->test_clear_monitor_trap_by_default();
    this->test_log_io_access_enabled();
    this->test_log_io_access_disabled();
    this->test_clear_io_access_log();
    this->test_handle_vmcall_overrun_denials_buffer();
    this->test_handle_vmcall_registers_unknown();
    this->test_handle_vmcall_registers_io_instruction_unknown();
    this->test_handle_vmcall_registers_io_instruction_trap_on_io_access_allowed();
    this->test_handle_vmcall_registers_io_instruction_trap_on_io_access_logged();
    this->test_handle_vmcall_registers_io_instruction_trap_on_io_access_denied();
    this->test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_allowed();
    this->test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_logged();
    this->test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_denied();
    this->test_handle_vmcall_registers_io_instruction_pass_through_io_access_allowed();
    this->test_handle_vmcall_registers_io_instruction_pass_through_io_access_logged();
    this->test_handle_vmcall_registers_io_instruction_pass_through_io_access_denied();
    this->test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_allowed();
    this->test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_logged();
    this->test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_denied();
    this->test_handle_vmcall_json_unknown();
    this->test_handle_vmcall_json_io_instruction_trap_on_io_access_missing_port();
    this->test_handle_vmcall_json_io_instruction_trap_on_io_access_invalid_port();
    this->test_handle_vmcall_json_io_instruction_trap_on_io_access_allowed();
    this->test_handle_vmcall_json_io_instruction_trap_on_io_access_logged();
    this->test_handle_vmcall_json_io_instruction_trap_on_io_access_denied();
    this->test_handle_vmcall_json_io_instruction_pass_through_io_access_missing_port();
    this->test_handle_vmcall_json_io_instruction_pass_through_io_access_invalid_port();
    this->test_handle_vmcall_json_io_instruction_pass_through_io_access_allowed();
    this->test_handle_vmcall_json_io_instruction_pass_through_io_access_logged();
    this->test_handle_vmcall_json_io_instruction_pass_through_io_access_denied();
    this->test_handle_vmcall_json_io_instruction_whitelist_io_access_missing_ports();
    this->test_handle_vmcall_json_io_instruction_whitelist_io_access_invalid_ports();
    this->test_handle_vmcall_json_io_instruction_whitelist_io_access_allowed();
    this->test_handle_vmcall_json_io_instruction_whitelist_io_access_logged();
    this->test_handle_vmcall_json_io_instruction_whitelist_io_access_denied();
    this->test_handle_vmcall_json_io_instruction_blacklist_io_access_missing_ports();
    this->test_handle_vmcall_json_io_instruction_blacklist_io_access_invalid_ports();
    this->test_handle_vmcall_json_io_instruction_blacklist_io_access_allowed();
    this->test_handle_vmcall_json_io_instruction_blacklist_io_access_logged();
    this->test_handle_vmcall_json_io_instruction_blacklist_io_access_denied();
    this->test_handle_vmcall_json_io_instruction_log_io_access_missing_enabled();
    this->test_handle_vmcall_json_io_instruction_log_io_access_invalid_enabled();
    this->test_handle_vmcall_json_io_instruction_log_io_access_allowed();
    this->test_handle_vmcall_json_io_instruction_log_io_access_logged();
    this->test_handle_vmcall_json_io_instruction_log_io_access_denied();
    this->test_handle_vmcall_json_io_instruction_clear_io_access_log_allowed();
    this->test_handle_vmcall_json_io_instruction_clear_io_access_log_logged();
    this->test_handle_vmcall_json_io_instruction_clear_io_access_log_denied();
    this->test_handle_vmcall_json_io_instruction_io_access_log_allowed();
    this->test_handle_vmcall_json_io_instruction_io_access_log_logged();
    this->test_handle_vmcall_json_io_instruction_io_access_log_denied();
    this->test_handle_vmcall_registers_vpid_unknown();
    this->test_handle_vmcall_registers_vpid_enable_vpid_allowed();
    this->test_handle_vmcall_registers_vpid_enable_vpid_logged();
    this->test_handle_vmcall_registers_vpid_enable_vpid_denied();
    this->test_handle_vmcall_registers_vpid_disable_vpid_allowed();
    this->test_handle_vmcall_registers_vpid_disable_vpid_logged();
    this->test_handle_vmcall_registers_vpid_disable_vpid_denied();
    this->test_handle_vmcall_json_vpid_enable_vpid_missing_enabled();
    this->test_handle_vmcall_json_vpid_enable_vpid_invalid_enabled();
    this->test_handle_vmcall_json_vpid_enable_vpid_allowed();
    this->test_handle_vmcall_json_vpid_enable_vpid_logged();
    this->test_handle_vmcall_json_vpid_enable_vpid_denied();
    this->test_handle_vmcall_json_verifiers_clear_denials_allowed();
    this->test_handle_vmcall_json_verifiers_clear_denials_logged();
    this->test_handle_vmcall_json_verifiers_clear_denials_denied();
    this->test_handle_vmcall_json_verifiers_dump_policy_allowed();
    this->test_handle_vmcall_json_verifiers_dump_policy_logged();
    this->test_handle_vmcall_json_verifiers_dump_policy_denied();
    this->test_handle_vmcall_json_verifiers_dump_denials_allowed();
    this->test_handle_vmcall_json_verifiers_dump_denials_logged();
    this->test_handle_vmcall_json_verifiers_dump_denials_denied();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(eapis_ut);
}
