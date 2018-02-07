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

#include "../../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/io_instruction_verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/vpid_verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/msr_verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/rdmsr_verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/wrmsr_verifiers.h"
#include "../../../../../include/hve/arch/intel_x64/exit_handler/cpuid_verifiers.h"

namespace exit_handler_eapis = eapis::hve::intel_x64::exit_handler;

void
exit_handler_eapis::exit_handler::init_policy()
{
    m_verifiers[vp::index_clear_denials] = std::make_unique<default_verifier__clear_denials>();
    m_verifiers[vp::index_dump_policy] = std::make_unique<default_verifier__dump_policy>();
    m_verifiers[vp::index_dump_denials] = std::make_unique<default_verifier__dump_denials>();

    m_verifiers[vp::index_enable_io_bitmaps] = std::make_unique<default_verifier__enable_io_bitmaps>();
    m_verifiers[vp::index_trap_on_io_access] = std::make_unique<default_verifier__trap_on_io_access>();
    m_verifiers[vp::index_trap_on_all_io_accesses] = std::make_unique<default_verifier__trap_on_all_io_accesses>();
    m_verifiers[vp::index_pass_through_io_access] = std::make_unique<default_verifier__pass_through_io_access>();
    m_verifiers[vp::index_pass_through_all_io_accesses] = std::make_unique<default_verifier__pass_through_all_io_accesses>();
    m_verifiers[vp::index_whitelist_io_access] = std::make_unique<default_verifier__whitelist_io_access>();
    m_verifiers[vp::index_blacklist_io_access] = std::make_unique<default_verifier__blacklist_io_access>();
    m_verifiers[vp::index_log_io_access] = std::make_unique<default_verifier__log_io_access>();
    m_verifiers[vp::index_clear_io_access_log] = std::make_unique<default_verifier__clear_io_access_log>();
    m_verifiers[vp::index_io_access_log] = std::make_unique<default_verifier__io_access_log>();

    m_verifiers[vp::index_enable_vpid] = std::make_unique<default_verifier__enable_vpid>();

    m_verifiers[vp::index_enable_msr_bitmap] = std::make_unique<default_verifier__enable_msr_bitmap>();

    m_verifiers[vp::index_trap_on_rdmsr_access] = std::make_unique<default_verifier__trap_on_rdmsr_access>();
    m_verifiers[vp::index_trap_on_all_rdmsr_accesses] = std::make_unique<default_verifier__trap_on_all_rdmsr_accesses>();
    m_verifiers[vp::index_pass_through_rdmsr_access] = std::make_unique<default_verifier__pass_through_rdmsr_access>();
    m_verifiers[vp::index_pass_through_all_rdmsr_accesses] = std::make_unique<default_verifier__pass_through_all_rdmsr_accesses>();
    m_verifiers[vp::index_whitelist_rdmsr_access] = std::make_unique<default_verifier__whitelist_rdmsr_access>();
    m_verifiers[vp::index_blacklist_rdmsr_access] = std::make_unique<default_verifier__blacklist_rdmsr_access>();
    m_verifiers[vp::index_log_rdmsr_access] = std::make_unique<default_verifier__log_rdmsr_access>();
    m_verifiers[vp::index_clear_rdmsr_access_log] = std::make_unique<default_verifier__clear_rdmsr_access_log>();
    m_verifiers[vp::index_rdmsr_access_log] = std::make_unique<default_verifier__rdmsr_access_log>();

    m_verifiers[vp::index_trap_on_wrmsr_access] = std::make_unique<default_verifier__trap_on_wrmsr_access>();
    m_verifiers[vp::index_trap_on_all_wrmsr_accesses] = std::make_unique<default_verifier__trap_on_all_wrmsr_accesses>();
    m_verifiers[vp::index_pass_through_wrmsr_access] = std::make_unique<default_verifier__pass_through_wrmsr_access>();
    m_verifiers[vp::index_pass_through_all_wrmsr_accesses] = std::make_unique<default_verifier__pass_through_all_wrmsr_accesses>();
    m_verifiers[vp::index_whitelist_wrmsr_access] = std::make_unique<default_verifier__whitelist_wrmsr_access>();
    m_verifiers[vp::index_blacklist_wrmsr_access] = std::make_unique<default_verifier__blacklist_wrmsr_access>();
    m_verifiers[vp::index_log_wrmsr_access] = std::make_unique<default_verifier__log_wrmsr_access>();
    m_verifiers[vp::index_clear_wrmsr_access_log] = std::make_unique<default_verifier__clear_wrmsr_access_log>();
    m_verifiers[vp::index_wrmsr_access_log] = std::make_unique<default_verifier__wrmsr_access_log>();

    m_verifiers[vp::index_emulate_cpuid] = std::make_unique<default_verifier__emulate_cpuid>();
    m_verifiers[vp::index_reset_cpuid_leaf] = std::make_unique<default_verifier__reset_cpuid_leaf>();
    m_verifiers[vp::index_reset_cpuid_all] = std::make_unique<default_verifier__reset_cpuid_all>();
    m_verifiers[vp::index_log_cpuid_access] = std::make_unique<default_verifier__log_cpuid_access>();
    m_verifiers[vp::index_clear_cpuid_access_log] = std::make_unique<default_verifier__clear_cpuid_access_log>();
    m_verifiers[vp::index_cpuid_access_log] = std::make_unique<default_verifier__cpuid_access_log>();
    m_verifiers[vp::index_dump_cpuid_emulations_log] = std::make_unique<default_verifier__dump_cpuid_emulations_log>();
}
