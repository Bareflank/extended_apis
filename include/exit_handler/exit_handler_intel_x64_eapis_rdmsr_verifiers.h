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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_RDMSR_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_RDMSR_VERIFIERS_H

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

/// @cond

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

namespace vp
{
constexpr const auto index_trap_on_rdmsr_access                   = 0x0004001UL;
constexpr const auto index_trap_on_all_rdmsr_accesses             = 0x0004002UL;
constexpr const auto index_pass_through_rdmsr_access              = 0x0004003UL;
constexpr const auto index_pass_through_all_rdmsr_accesses        = 0x0004004UL;
constexpr const auto index_whitelist_rdmsr_access                 = 0x0004005UL;
constexpr const auto index_blacklist_rdmsr_access                 = 0x0004006UL;
constexpr const auto index_log_rdmsr_access                       = 0x0004007UL;
constexpr const auto index_clear_rdmsr_access_log                 = 0x0004008UL;
constexpr const auto index_rdmsr_access_log                       = 0x0004009UL;
}

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_EXIT_HANDLER
#ifdef SHARED_EAPIS_EXIT_HANDLER
#define EXPORT_EAPIS_EXIT_HANDLER EXPORT_SYM
#else
#define EXPORT_EAPIS_EXIT_HANDLER IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_EXIT_HANDLER
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__trap_on_rdmsr_access :
    public vmcall_verifier
{
public:
    default_verifier__trap_on_rdmsr_access() = default;
    ~default_verifier__trap_on_rdmsr_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::msr_type msr)
    { bfignored(msr); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__trap_on_all_rdmsr_accesses :
    public vmcall_verifier
{
public:
    default_verifier__trap_on_all_rdmsr_accesses() = default;
    ~default_verifier__trap_on_all_rdmsr_accesses() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__pass_through_rdmsr_access :
    public vmcall_verifier
{
public:
    default_verifier__pass_through_rdmsr_access() = default;
    ~default_verifier__pass_through_rdmsr_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::msr_type msr)
    { bfignored(msr); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__pass_through_all_rdmsr_accesses :
    public vmcall_verifier
{
public:
    default_verifier__pass_through_all_rdmsr_accesses() = default;
    ~default_verifier__pass_through_all_rdmsr_accesses() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__whitelist_rdmsr_access :
    public vmcall_verifier
{
public:
    default_verifier__whitelist_rdmsr_access() = default;
    ~default_verifier__whitelist_rdmsr_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::msr_list_type msrs)
    { bfignored(msrs); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__blacklist_rdmsr_access :
    public vmcall_verifier
{
public:
    default_verifier__blacklist_rdmsr_access() = default;
    ~default_verifier__blacklist_rdmsr_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::msr_list_type msrs)
    { bfignored(msrs); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__log_rdmsr_access :
    public vmcall_verifier
{
public:
    default_verifier__log_rdmsr_access() = default;
    ~default_verifier__log_rdmsr_access() override = default;

    virtual verifier_result verify(bool enabled)
    { bfignored(enabled); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__clear_rdmsr_access_log :
    public vmcall_verifier
{
public:
    default_verifier__clear_rdmsr_access_log() = default;
    ~default_verifier__clear_rdmsr_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__rdmsr_access_log :
    public vmcall_verifier
{
public:
    default_verifier__rdmsr_access_log() = default;
    ~default_verifier__rdmsr_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

/// @endcond

#endif
