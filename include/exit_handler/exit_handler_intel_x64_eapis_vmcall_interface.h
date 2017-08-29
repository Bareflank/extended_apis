/*
 * Bareflank Extended APIs
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_VMCALL_INTERFACE_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_VMCALL_INTERFACE_H

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extended APIs VMCall Categories
 */
enum eapis_vmcall_categories {
    eapis_cat__io_instruction = 0x1000,
    eapis_cat__vpid = 0x2000,
    eapis_cat__msr = 0x3000,
    eapis_cat__rdmsr = 0x4000,
    eapis_cat__wrmsr = 0x5000,
};

/**
 * Extended APIs VMCall Functions
 */
enum eapis_vmcall_functions {
    eapis_fun__enable_io_bitmaps = 0x1,
    eapis_fun__disable_io_bitmaps = 0x2,
    eapis_fun__trap_on_io_access = 0x3,
    eapis_fun__trap_on_all_io_accesses = 0x4,
    eapis_fun__pass_through_io_access = 0x5,
    eapis_fun__pass_through_all_io_accesses = 0x6,

    eapis_fun__enable_vpid = 0x1,
    eapis_fun__disable_vpid = 0x2,

    eapis_fun__enable_msr_bitmap = 0x1,
    eapis_fun__disable_msr_bitmap = 0x2,

    eapis_fun__trap_on_rdmsr_access = 0x1,
    eapis_fun__trap_on_all_rdmsr_accesses = 0x2,
    eapis_fun__pass_through_rdmsr_access = 0x3,
    eapis_fun__pass_through_all_rdmsr_accesses = 0x4,

    eapis_fun__trap_on_wrmsr_access = 0x1,
    eapis_fun__trap_on_all_wrmsr_accesses = 0x2,
    eapis_fun__pass_through_wrmsr_access = 0x3,
    eapis_fun__pass_through_all_wrmsr_accesses = 0x4,
};

/**
 * @page eapis_vmcalls Extended APIs VMCalls
 *
 * @tableofcontents
 *
 * @section vmcall_denials VMCall Denials
 *
 * @subsection vmcall_denials_register Register Based VMCalls
 * There are no register based vmcalls for vmcall denials
 *
 * @subsection vmcall_denials_json JSON Based VMCalls
 *
 * <b>{"command":"clear_denials"}</b>:
 * Clears the list of vmcall denials
 *
 * <b>{"command":"dump_policy"}</b>:
 * Returns a list of verifiers and their denial policies
 *
 * <b>{"command":"dump_denials"}</b>:
 * Returns a list of denied vmcalls
 *
 *
 *
 * @section io_instruction IO Instruction
 *
 * @subsection io_instruction_register Register Based VMCalls
 *
 * <b>enable_io_bitmaps</b>:
 * Instructs the hypervisor to enable IO bitmaps
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__enable_io_bitmaps
 *
 * <b>disable_io_bitmaps</b>:
 * Instructs the hypervisor to disable IO bitmaps
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__disable_io_bitmaps
 *
 * <b>trap_on_io_access</b>:
 * Instructs the hypervisor to trap on the provided port
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__trap_on_io_access
 * - r04 = port #
 *
 * <b>trap_on_all_io_accesses</b>:
 * Instructs the hypervisor to trap on all ports
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__trap_on_all_io_accesses
 *
 * <b>pass_through_io_access</b>:
 * Instructs the hypervisor to pass through the provided port
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__pass_through_io_access
 * - r04 = port #
 *
 * <b>pass_through_all_io_accesses</b>:
 * Instructs the hypervisor to pass through all ports
 * - r02 = eapis_cat__io_instruction
 * - r03 = eapis_fun__pass_through_all_io_accesses
 *
 * @subsection io_instruction_json JSON Based VMCalls
 *
 * <b>{"command":"enable_io_bitmaps", "enabled": true/false}</b>:
 * Instructs the hypervisor to enable/disable IO bitmaps
 *
 * <b>{"command":"trap_on_io_access", "port": dec}</b>:
 * <b>{"command":"trap_on_io_access", "port_hex": "hex"}</b>:
 * Instructs the hypervisor to trap on the provided port
 *
 * <b>{"command":"pass_through_io_access", "port": dec}</b>:
 * <b>{"command":"pass_through_io_access", "port_hex": "hex"}</b>:
 * Instructs the hypervisor to pass through the provided port
 *
 * <b>{"command":"whitelist_io_access", "ports": [dec]}</b>:
 * <b>{"command":"whitelist_io_access", "ports_hex": ["hex"]}</b>:
 * Instructs the hypervisor to trap on all ports minus the ports provided
 *
 * <b>{"command":"blacklist_io_access", "ports": [dec]}</b>:
 * <b>{"command":"blacklist_io_access", "ports_hex": ["hex"]}</b>:
 * Instructs the hypervisor to pass through all ports minus the ports provided
 *
 * <b>{"command":"log_io_access", "enabled": true/false}</b>:
 * Instructs the hypervisor to log trapped IO access
 *
 * <b>{"command":"clear_io_access_log"}</b>:
 * Clears logged IO accesses
 *
 * <b>{"command":"io_access_log"}</b>:
 * Returns the list of logged IO accesses
 *
 *
 *
 * @section vpid VPID
 *
 * @subsection vpid_register Register Based VMCalls
 *
 * <b>enable_vpid</b>:
 * Instructs the hypervisor to enable VPID
 * - r02 = eapis_cat__vpid
 * - r03 = eapis_fun__enable_vpid
 *
 * <b>disable_vpid</b>:
 * Instructs the hypervisor to disable VPID
 * - r02 = eapis_cat__vpid
 * - r03 = eapis_fun__disable_vpid
 *
 * @subsection vpid_json JSON Based VMCalls
 *
 * <b>{"command":"enable_vpid", "enabled": true/false}</b>:
 * Instructs the hypervisor to enable/disable vpid
 *
 *
 *
 * @section msr MSR
 *
 * @subsection msr_register Register Based VMCalls
 *
 * <b>enable_msr_bitmap</b>:
 * Instructs the hypervisor to enable IO bitmaps
 * - r02 = eapis_cat__msr
 * - r03 = eapis_fun__enable_msr_bitmap
 *
 * <b>disable_msr_bitmap</b>:
 * Instructs the hypervisor to disable IO bitmaps
 * - r02 = eapis_cat__msr
 * - r03 = eapis_fun__disable_msr_bitmap
 *
 * @subsection msr_json JSON Based VMCalls
 *
 * <b>{"command":"enable_msr_bitmap", "enabled": true/false}</b>:
 * Instructs the hypervisor to enable/disable IO bitmaps
 *
 *
 *
 * @section rdmsr Read MSR
 *
 * @subsection rdmsr_register Register Based VMCalls
 *
 * <b>trap_on_rdmsr_access</b>:
 * Instructs the hypervisor to trap on the provided msr
 * - r02 = eapis_cat__rdmsr
 * - r03 = eapis_fun__trap_on_rdmsr_access
 * - r04 = msr #
 *
 * <b>trap_on_all_rdmsr_accesses</b>:
 * Instructs the hypervisor to trap on all msrs
 * - r02 = eapis_cat__rdmsr
 * - r03 = eapis_fun__trap_on_all_rdmsr_accesses
 *
 * <b>pass_through_rdmsr_access</b>:
 * Instructs the hypervisor to pass through the provided msr
 * - r02 = eapis_cat__rdmsr
 * - r03 = eapis_fun__pass_through_rdmsr_access
 * - r04 = msr #
 *
 * <b>pass_through_all_rdmsr_accesses</b>:
 * Instructs the hypervisor to pass through all msrs
 * - r02 = eapis_cat__rdmsr
 * - r03 = eapis_fun__pass_through_all_rdmsr_accesses
 *
 * @subsection rdmsr_json JSON Based VMCalls
 *
 * <b>{"command":"trap_on_rdmsr_access", "msr": dec}</b>:
 * <b>{"command":"trap_on_rdmsr_access", "msr_hex": "hex"}</b>:
 * Instructs the hypervisor to trap on the provided msr
 *
 * <b>{"command":"pass_through_rdmsr_access", "msr": dec}</b>:
 * <b>{"command":"pass_through_rdmsr_access", "msr_hex": "hex"}</b>:
 * Instructs the hypervisor to pass through the provided msr
 *
 * <b>{"command":"whitelist_rdmsr_access", "msrs": [dec]}</b>:
 * <b>{"command":"whitelist_rdmsr_access", "msrs_hex": ["hex"]}</b>:
 * Instructs the hypervisor to trap on all msrs minus the msrs provided
 *
 * <b>{"command":"blacklist_rdmsr_access", "msrs": [dec]}</b>:
 * <b>{"command":"blacklist_rdmsr_access", "msrs_hex": ["hex"]}</b>:
 * Instructs the hypervisor to pass through all msrs minus the msrs provided
 *
 * <b>{"command":"log_rdmsr_access", "enabled": true/false}</b>:
 * Instructs the hypervisor to log trapped MSR access
 *
 * <b>{"command":"clear_rdmsr_access_log"}</b>:
 * Clears logged MSR accesses
 *
 * <b>{"command":"rdmsr_access_log"}</b>:
 * Returns the list of logged MSR accesses
 *
 *
 *
 * @section wrmsr Write MSR
 *
 * @subsection wrmsr_register Register Based VMCalls
 *
 * <b>trap_on_wrmsr_access</b>:
 * Instructs the hypervisor to trap on the provided msr
 * - r02 = eapis_cat__wrmsr
 * - r03 = eapis_fun__trap_on_wrmsr_access
 * - r04 = msr #
 *
 * <b>trap_on_all_wrmsr_accesses</b>:
 * Instructs the hypervisor to trap on all msrs
 * - r02 = eapis_cat__wrmsr
 * - r03 = eapis_fun__trap_on_all_wrmsr_accesses
 *
 * <b>pass_through_wrmsr_access</b>:
 * Instructs the hypervisor to pass through the provided msr
 * - r02 = eapis_cat__wrmsr
 * - r03 = eapis_fun__pass_through_wrmsr_access
 * - r04 = msr #
 *
 * <b>pass_through_all_wrmsr_accesses</b>:
 * Instructs the hypervisor to pass through all msrs
 * - r02 = eapis_cat__wrmsr
 * - r03 = eapis_fun__pass_through_all_wrmsr_accesses
 *
 * @subsection wrmsr_json JSON Based VMCalls
 *
 * <b>{"command":"trap_on_wrmsr_access", "msr": dec}</b>:
 * <b>{"command":"trap_on_wrmsr_access", "msr_hex": "hex"}</b>:
 * Instructs the hypervisor to trap on the provided msr
 *
 * <b>{"command":"pass_through_wrmsr_access", "msr": dec}</b>:
 * <b>{"command":"pass_through_wrmsr_access", "msr_hex": "hex"}</b>:
 * Instructs the hypervisor to pass through the provided msr
 *
 * <b>{"command":"whitelist_wrmsr_access", "msrs": [dec]}</b>:
 * <b>{"command":"whitelist_wrmsr_access", "msrs_hex": ["hex"]}</b>:
 * Instructs the hypervisor to trap on all msrs minus the msrs provided
 *
 * <b>{"command":"blacklist_wrmsr_access", "msrs": [dec]}</b>:
 * <b>{"command":"blacklist_wrmsr_access", "msrs_hex": ["hex"]}</b>:
 * Instructs the hypervisor to pass through all msrs minus the msrs provided
 *
 * <b>{"command":"log_wrmsr_access", "enabled": true/false}</b>:
 * Instructs the hypervisor to log trapped MSR access
 *
 * <b>{"command":"clear_wrmsr_access_log"}</b>:
 * Clears logged MSR accesses
 *
 * <b>{"command":"wrmsr_access_log"}</b>:
 * Returns the list of logged MSR accesses
 *
 */

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
