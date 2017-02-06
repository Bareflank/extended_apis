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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_VERIFIERS_H

#ifndef DENIAL_LOG_SIZE
#define DENIAL_LOG_SIZE 25
#endif

#include <string>

class vmcall_verifier
{
public:

    using denial_list_type = std::vector<std::string>;

    enum verifier_result
    {
        deny = 0,
        log = 1,
        allow = 2,
    };

public:
    vmcall_verifier() = default;
    virtual ~vmcall_verifier() = default;

    virtual std::string to_string() const;

    verifier_result default_verify();
    void deny_vmcall_with_args(const char *func, denial_list_type &list);
};

class default_verifier__clear_denials : public vmcall_verifier
{
public:
    default_verifier__clear_denials() = default;
    ~default_verifier__clear_denials() override = default;

    verifier_result verify()
    { return default_verify(); }
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

constexpr const auto index_clear_denials                          = 0x0000001UL;
constexpr const auto index_dump_policy                            = 0x0000002UL;
constexpr const auto index_dump_denials                           = 0x0000003UL;

constexpr const auto index_enable_io_bitmaps                      = 0x0001001UL;
constexpr const auto index_trap_on_io_access                      = 0x0001002UL;
constexpr const auto index_trap_on_all_io_accesses                = 0x0001003UL;
constexpr const auto index_pass_through_io_access                 = 0x0001004UL;
constexpr const auto index_pass_through_all_io_accesses           = 0x0001005UL;
constexpr const auto index_whitelist_io_access                    = 0x0001006UL;
constexpr const auto index_blacklist_io_access                    = 0x0001007UL;
constexpr const auto index_log_io_access                          = 0x0001008UL;
constexpr const auto index_clear_io_access_log                    = 0x0001009UL;
constexpr const auto index_io_access_log                          = 0x000100AUL;

constexpr const auto index_enable_vpid                            = 0x0002001UL;

constexpr const auto index_enable_msr_bitmap                      = 0x0003001UL;

constexpr const auto index_trap_on_rdmsr_access                   = 0x0004001UL;
constexpr const auto index_trap_on_all_rdmsr_accesses             = 0x0004002UL;
constexpr const auto index_pass_through_rdmsr_access              = 0x0004003UL;
constexpr const auto index_pass_through_all_rdmsr_accesses        = 0x0004004UL;
constexpr const auto index_whitelist_rdmsr_access                 = 0x0004005UL;
constexpr const auto index_blacklist_rdmsr_access                 = 0x0004006UL;
constexpr const auto index_log_rdmsr_access                       = 0x0004007UL;
constexpr const auto index_clear_rdmsr_access_log                 = 0x0004008UL;
constexpr const auto index_rdmsr_access_log                       = 0x0004009UL;

constexpr const auto index_trap_on_wrmsr_access                   = 0x0004001UL;
constexpr const auto index_trap_on_all_wrmsr_accesses             = 0x0004002UL;
constexpr const auto index_pass_through_wrmsr_access              = 0x0004003UL;
constexpr const auto index_pass_through_all_wrmsr_accesses        = 0x0004004UL;
constexpr const auto index_whitelist_wrmsr_access                 = 0x0004005UL;
constexpr const auto index_blacklist_wrmsr_access                 = 0x0004006UL;
constexpr const auto index_log_wrmsr_access                       = 0x0004007UL;
constexpr const auto index_clear_wrmsr_access_log                 = 0x0004008UL;
constexpr const auto index_wrmsr_access_log                       = 0x0004009UL;

}

#define policy(a) \
    this->get_verifier<default_verifier__ ## a>(vp::index_ ## a)

#define deny_vmcall() \
    deny_vmcall_with_args(__FUNC__, m_denials)

#endif
