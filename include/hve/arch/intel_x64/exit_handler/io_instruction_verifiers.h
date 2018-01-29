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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_IO_INSTRUCTION_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_IO_INSTRUCTION_VERIFIERS_H

#include <hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <hve/arch/intel_x64/exit_handler/verifiers.h>

/// @cond

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

namespace vp
{
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

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__enable_io_bitmaps :
    public vmcall_verifier
{
public:
    default_verifier__enable_io_bitmaps() = default;
    ~default_verifier__enable_io_bitmaps() override = default;

    virtual verifier_result verify(bool enabled)
    { bfignored(enabled); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__trap_on_io_access :
    public vmcall_verifier
{
public:
    default_verifier__trap_on_io_access() = default;
    ~default_verifier__trap_on_io_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::port_type port)
    { bfignored(port); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__trap_on_all_io_accesses :
    public vmcall_verifier
{
public:
    default_verifier__trap_on_all_io_accesses() = default;
    ~default_verifier__trap_on_all_io_accesses() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__pass_through_io_access :
    public vmcall_verifier
{
public:
    default_verifier__pass_through_io_access() = default;
    ~default_verifier__pass_through_io_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::port_type port)
    { bfignored(port); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__pass_through_all_io_accesses :
    public vmcall_verifier
{
public:
    default_verifier__pass_through_all_io_accesses() = default;
    ~default_verifier__pass_through_all_io_accesses() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__whitelist_io_access :
    public vmcall_verifier
{
public:
    default_verifier__whitelist_io_access() = default;
    ~default_verifier__whitelist_io_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::port_list_type ports)
    { bfignored(ports); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__blacklist_io_access :
    public vmcall_verifier
{
public:
    default_verifier__blacklist_io_access() = default;
    ~default_verifier__blacklist_io_access() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::port_list_type ports)
    { bfignored(ports); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__log_io_access :
    public vmcall_verifier
{
public:
    default_verifier__log_io_access() = default;
    ~default_verifier__log_io_access() override = default;

    virtual verifier_result verify(bool enabled)
    { bfignored(enabled); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__clear_io_access_log :
    public vmcall_verifier
{
public:
    default_verifier__clear_io_access_log() = default;
    ~default_verifier__clear_io_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__io_access_log :
    public vmcall_verifier
{
public:
    default_verifier__io_access_log() = default;
    ~default_verifier__io_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

/// @endcond

#endif
