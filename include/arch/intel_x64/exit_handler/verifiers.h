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
#include <bfdebug.h>

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

namespace vp
{
using index_type = uint64_t;

constexpr const auto index_clear_denials                          = 0x0000001UL;
constexpr const auto index_dump_policy                            = 0x0000002UL;
constexpr const auto index_dump_denials                           = 0x0000003UL;
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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// VMCall Verifier
///
/// This class defines the base class for vmcall verification. The Extended APIs
/// provides a set of default verifiers that are always allowed, or deny all.
/// These classes are intended to be subclassed to provide more fine grain
/// control of your vmcall policy using a policy engine such as FLASK.
///
class EXPORT_EAPIS_EXIT_HANDLER vmcall_verifier
{
public:

    using denial_list_type = std::vector<std::string>;      ///< Denial list type

    /// Verifier Result
    ///
    enum verifier_result {
        deny = 0,
        log = 1,
        allow = 2,
    };

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    vmcall_verifier() = default;

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vmcall_verifier() = default;

    /// To String
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a human readable version of the verifier
    ///
    virtual std::string to_string() const;

    /// Default Verifier
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns
    ///     - deny if ENABLE_VMCALL_DENIALS == 1
    ///     - log if ENABLE_VMCALL_DENIALS == 2
    ///     - allow otherwise
    ///
    verifier_result default_verify();

    /// Deny VMCall
    ///
    /// @expects none
    /// @ensures none
    ///
    /// Used to deny a vmcall. Must provide the vmcall that was denied
    /// as well as the list the denial is being added too.
    ///
    /// @param func the name of the vmcall function being denied
    /// @param list the denial list to add the denial too
    ///
    void deny_vmcall_with_args(const char *func, denial_list_type &list);
};

/// @cond

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__clear_denials :
    public vmcall_verifier
{
public:
    default_verifier__clear_denials() = default;
    ~default_verifier__clear_denials() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__dump_policy :
    public vmcall_verifier
{
public:
    default_verifier__dump_policy() = default;
    ~default_verifier__dump_policy() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

class EXPORT_EAPIS_EXIT_HANDLER default_verifier__dump_denials :
    public vmcall_verifier
{
public:
    default_verifier__dump_denials() = default;
    ~default_verifier__dump_denials() override = default;

    virtual verifier_result verify()
    { return default_verify(); }
};

/// @endcond

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

/// @cond

#define policy(a) \
    this->get_verifier<default_verifier__ ## a>(vp::index_ ## a)

#define deny_vmcall() \
    deny_vmcall_with_args(__BFFUNC__, m_denials)

/// @endcond

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
