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

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

#include <memory>
#include <hippomocks.h>

#include <bfgsl.h>

#include <intrinsics/x86/intel_x64.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

extern std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
extern std::map<intel_x64::vmcs::field_type, intel_x64::vmcs::value_type> g_vmcs;

extern uintptr_t g_rip;
extern state_save_intel_x64 g_state_save;
extern bool g_monitor_trap_callback_called;

extern bool g_enable_vpid;
extern bool g_enable_io_bitmaps;
extern bool g_enable_msr_bitmap;
extern exit_handler_intel_x64_eapis::port_type g_port;
extern exit_handler_intel_x64_eapis::msr_type g_rdmsr;
extern exit_handler_intel_x64_eapis::msr_type g_wrmsr;

extern bool g_deny_all;
extern bool g_log_denials;

class exit_handler_ut : public exit_handler_intel_x64_eapis
{
public:
    void monitor_trap_callback()
    { g_monitor_trap_callback_called = true; }
};

vmcs_intel_x64_eapis *setup_vmcs(MockRepository &mocks,
                                 intel_x64::vmcs::value_type reason, intel_x64::vmcs::value_type qualification = 0);
std::unique_ptr<exit_handler_ut> setup_ehlr(gsl::not_null<vmcs_intel_x64_eapis *> vmcs);

#endif
