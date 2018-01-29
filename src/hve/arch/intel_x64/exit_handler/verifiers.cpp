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

#include <bfstring.h>
#include <bfexports.h>

#include <hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <hve/arch/intel_x64/exit_handler/verifiers.h>

//#define ENABLE_VMCALL_DENIALS 1 // Enables Deny All
//#define ENABLE_VMCALL_DENIALS 2 // Enabled Logging

#if ENABLE_VMCALL_DENIALS == 1
EXPORT_SYM bool g_deny_all = true;
EXPORT_SYM bool g_log_denials = true;
#elif ENABLE_VMCALL_DENIALS == 2
EXPORT_SYM bool g_deny_all = false;
EXPORT_SYM bool g_log_denials = true;
#else
EXPORT_SYM bool g_deny_all = false;
EXPORT_SYM bool g_log_denials = false;
#endif

std::string
vmcall_verifier::to_string() const
{
    if (g_deny_all) {
        return "deny all";
    }

    if (g_log_denials) {
        return "ignore and log all";
    }

    return "allow all";
}

vmcall_verifier::verifier_result
vmcall_verifier::default_verify()
{
    if (g_deny_all) {
        return deny;
    }

    if (g_log_denials) {
        return log;
    }

    return allow;
}

void
vmcall_verifier::deny_vmcall_with_args(const char *func, denial_list_type &list)
{
    auto msg = "vmcall denied ["_s + func + "]: "_s + to_string();

    if (g_log_denials) {
        if (list.size() >= DENIAL_LOG_SIZE) {
            list.erase(list.begin());
        }

        list.push_back(msg);
    }

    if (g_deny_all) {
        throw std::runtime_error(msg);
    }
}
