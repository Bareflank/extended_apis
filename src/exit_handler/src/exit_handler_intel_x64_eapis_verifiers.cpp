//
// Bareflank Hypervisor Examples
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

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

//#define ENABLE_VMCALL_DENIALS 1 // Enables Deny All
//#define ENABLE_VMCALL_DENIALS 2 // Enabled Logging

#if ENABLE_VMCALL_DENIALS == 1
bool g_deny_all = true;
bool g_log_denials = true;
#elif ENABLE_VMCALL_DENIALS == 2
bool g_deny_all = false;
bool g_log_denials = true;
#else
bool g_deny_all = false;
bool g_log_denials = false;
#endif

std::string
vmcall_verifier::to_string() const
{
    if (g_deny_all) return "deny all";
    if (g_log_denials) return "ignore and log all";

    return "allow all";
}

vmcall_verifier::verifier_result
vmcall_verifier::default_verify()
{
    if (g_deny_all) return deny;
    if (g_log_denials) return log;

    return allow;
}

void
vmcall_verifier::deny_vmcall_with_args(const char *func, denial_list_type &list)
{
    auto msg = "vmcall denied ["_s + func + "]: "_s + to_string();

    if (g_log_denials)
    {
        if (list.size() >= DENIAL_LOG_SIZE)
            list.erase(list.begin());

        list.push_back(msg);
    }

    if (g_deny_all)
        throw std::runtime_error(msg);
}
