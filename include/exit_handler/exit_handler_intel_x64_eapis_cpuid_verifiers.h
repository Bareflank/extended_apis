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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_CPUID_VERIFIERS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_CPUID_VERIFIERS_H

#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

/// @cond

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

namespace vp
{
constexpr const auto index_emulate_cpuid                          = 0x0006001UL;
constexpr const auto index_reset_cpuid_leaf                       = 0x0006002UL;
constexpr const auto index_reset_cpuid_all                        = 0x0006003UL;
constexpr const auto index_log_cpuid_access                       = 0x0006004UL;
constexpr const auto index_clear_cpuid_access_log                 = 0x0006005UL;
constexpr const auto index_cpuid_access_log                       = 0x0006006UL;
constexpr const auto index_dump_cpuid_emulations_log              = 0x0006007UL;
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

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__emulate_cpuid :
    public vmcall_verifier
{
public:
    default_verifier__emulate_cpuid() = default;
    ~default_verifier__emulate_cpuid() override = default;

    void check_string(std::string str)
    {
        auto msg = "vmcall denied [emulate_cpuid]: " + to_string();
        if (str.size() != 32) {
            throw std::runtime_error(msg);
        }
        for (auto c : str) {
            switch (c) {
                case '0':
                case '1':
                case '-':
                    break;

                default:
                    throw std::runtime_error(msg);
            }
        }
    }

    virtual verifier_result verify(
        exit_handler_intel_x64_eapis::cpuid_type leaf,
        exit_handler_intel_x64_eapis::cpuid_type subleaf,
        std::string eax, std::string ebx, std::string ecx, std::string edx)
    {
        bfignored(leaf);
        bfignored(subleaf);

        check_string(eax);
        check_string(ebx);
        check_string(ecx);
        check_string(edx);

        return default_verify();
    }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__reset_cpuid_leaf :
    public vmcall_verifier
{
public:
    default_verifier__reset_cpuid_leaf() = default;
    ~default_verifier__reset_cpuid_leaf() override = default;

    virtual verifier_result verify(exit_handler_intel_x64_eapis::cpuid_type leaf,
                                   exit_handler_intel_x64_eapis::cpuid_type subleaf)
    { bfignored(leaf); bfignored(subleaf); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__reset_cpuid_all :
    public vmcall_verifier
{
public:
    default_verifier__reset_cpuid_all() = default;
    ~default_verifier__reset_cpuid_all() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__log_cpuid_access :
    public vmcall_verifier
{
public:
    default_verifier__log_cpuid_access() = default;
    ~default_verifier__log_cpuid_access() override = default;

    virtual verifier_result verify(bool enabled)
    { bfignored(enabled); return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__clear_cpuid_access_log :
    public vmcall_verifier
{
public:
    default_verifier__clear_cpuid_access_log() = default;
    ~default_verifier__clear_cpuid_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__cpuid_access_log :
    public vmcall_verifier
{
public:
    default_verifier__cpuid_access_log() = default;
    ~default_verifier__cpuid_access_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__dump_cpuid_emulations_log :
    public vmcall_verifier
{
public:
    default_verifier__dump_cpuid_emulations_log() = default;
    ~default_verifier__dump_cpuid_emulations_log() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

/// @endcond

#endif
