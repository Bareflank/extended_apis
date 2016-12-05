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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_VERIFIERS_H

//#define ENABLE_VMCALL_DENIALS 1 // Enables Deny All
//#define ENABLE_VMCALL_DENIALS 2 // Enabled Logging

#if ENABLE_VMCALL_DENIALS == 1
constexpr const auto g_deny_all = true;
constexpr const auto g_log_denials = true;
#elif ENABLE_VMCALL_DENIALS == 2
constexpr const auto g_deny_all = false;
constexpr const auto g_log_denials = true;
#else
constexpr const auto g_deny_all = false;
constexpr const auto g_log_denials = false;
#endif

class vmcall_verifier
{
public:

    enum verifier_result
    {
        deny = 0,
        log = 1,
        allow = 2,
    };

public:
    vmcall_verifier() = default;
    virtual ~vmcall_verifier() = default;

    virtual std::string to_string() const
    { return g_deny_all ? "deny all" : "ignore all"; }

    verifier_result default_verify()
    {
        if (g_deny_all) return deny;
        if (g_log_denials) return log;

        return allow;
    }

    void deny_vmcall_with_args(const char *func, std::vector<std::string> &list)
    {
        auto msg = "vmcall denied ["_s + func + "]: "_s + to_string();

        if (g_log_denials)
            list.push_back(msg);

        if (g_deny_all)
            throw std::runtime_error(msg);
    }
};

class default_verifier__dump_policy : public vmcall_verifier
{
public:
    default_verifier__dump_policy() = default;
    ~default_verifier__dump_policy() override = default;

    verifier_result verify()
    { return default_verify(); }
};

class default_verifier__dump_denials : public vmcall_verifier
{
public:
    default_verifier__dump_denials() = default;
    ~default_verifier__dump_denials() override = default;

    verifier_result verify()
    { return default_verify(); }
};

namespace vp
{
using index_type = uint64_t;

constexpr const auto index_dump_policy                         = 0x0000001UL;
constexpr const auto index_dump_denials                        = 0x0000002UL;

constexpr const auto index_trap_on_io_access                   = 0x0001001UL;
constexpr const auto index_trap_on_all_io_accesses             = 0x0001002UL;
constexpr const auto index_pass_through_io_access              = 0x0001003UL;
constexpr const auto index_pass_through_all_io_accesses        = 0x0001004UL;
constexpr const auto index_whitelist_io_access                 = 0x0001005UL;
constexpr const auto index_blacklist_io_access                 = 0x0001006UL;
constexpr const auto index_log_io_access                       = 0x0001007UL;
constexpr const auto index_clear_io_access_log                 = 0x0001008UL;
constexpr const auto index_io_access_log                       = 0x0001009UL;
}

#define policy(a) \
    this->get_verifier<default_verifier__ ## a>(vp::index_ ## a)

#define deny_vmcall() \
    deny_vmcall_with_args(__FUNC__, m_denials)

#include <exit_handler/exit_handler_intel_x64_eapis_io_instruction_verifiers.h>

#endif
