/*
 * Bareflank Hypervisor
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

/*
 * Extended APIs VMCall Categories
 */
enum eapis_vmcall_categories
{
    eapis_cat__io_instruction = 0x1000,
    eapis_cat__vpid = 0x2000,
};

/*
 * Extended APIs VMCall Functions
 */
enum eapis_vmcall_functions
{
    /**
     * trap_on_io_access
     *
     * r2 = eapis_cat__io_instruction
     * r3 = eapis_fun__trap_on_io_access
     * r4 = port #
     *
     * calls: vmcs::trap_on_io_access
     */
    eapis_fun__trap_on_io_access = 0x1,

    /**
     * trap_on_io_access
     *
     * r2 = eapis_cat__io_instruction
     * r3 = eapis_fun__trap_on_all_io_accesses
     *
     * calls: vmcs::trap_on_all_io_accesses
     */
    eapis_fun__trap_on_all_io_accesses = 0x2,

    /**
     * pass_through_io_access
     *
     * r2 = eapis_cat__io_instruction
     * r3 = eapis_fun__pass_through_io_access
     * r4 = port #
     *
     * calls: vmcs::pass_through_io_access
     */
    eapis_fun__pass_through_io_access = 0x3,

    /**
     * pass_through_all_io_accesses
     *
     * r2 = eapis_cat__io_instruction
     * r3 = eapis_fun__pass_through_all_io_accesses
     *
     * calls: vmcs::pass_through_all_io_accesses
     */
    eapis_fun__pass_through_all_io_accesses = 0x4,

    /**
     * enable_vpid
     *
     * r2 = eapis_cat__vpid
     * r3 = eapis_fun__enable_vpid
     *
     * calls: vmcs::enable_vpid
     */
    eapis_fun__enable_vpid = 0x1,

    /**
     * disable_vpid
     *
     * r2 = eapis_cat__vpid
     * r3 = eapis_fun__disable_vpid
     *
     * calls: vmcs::disable_vpid
     */
    eapis_fun__disable_vpid = 0x2,
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
