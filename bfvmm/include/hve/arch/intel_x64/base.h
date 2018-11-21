//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef BASE_INTEL_X64_EAPIS_H
#define BASE_INTEL_X64_EAPIS_H

#include <bfgsl.h>

#include <list>
#include <unordered_map>

#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>

#ifndef EAPIS_LOG_MAX
#define EAPIS_LOG_MAX 10
#endif

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Namespaces
// -----------------------------------------------------------------------------

namespace vmcs_n = ::intel_x64::vmcs;

// -----------------------------------------------------------------------------
// Aliases
// -----------------------------------------------------------------------------

using vmcs_t = bfvmm::intel_x64::vmcs;
using exit_handler_t = bfvmm::intel_x64::exit_handler;

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

/// Base
///
/// Provides an interface for shared features of handlers for the various
/// exit reasons. New exit reasons may be handled by extending this class
/// with the relevant exit-reason-specific code.
///
class EXPORT_EAPIS_HVE base
{

public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    base() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~base() = default;

public:

    /// Enable Log
    ///
    /// Example:
    /// @code
    /// this->enable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_log()
    { m_log_enabled = true; }

    /// Disable Log
    ///
    /// Example:
    /// @code
    /// this->disable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_log()
    { m_log_enabled = false; }

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void dump_log() = 0;

    /// Add Record to Log
    ///
    /// Example:
    /// @code
    /// this->add_record();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param log The log to add a record to
    /// @param record The record to add to the log
    ///
    template<typename T> void
    add_record(std::list<T> &log, const T &record)
    {
        if (log.size() < EAPIS_LOG_MAX) {
            log.push_back(record);
        }
    }

protected:

    /// Log enabled
    ///
    /// If true, *each* class derived from base will log exit-reason-specific
    /// information on exit (provided also that NDEBUG == 0).
    //
    bool m_log_enabled{false};

public:

    /// @cond

    base(base &&) = default;
    base &operator=(base &&) = default;

    base(const base &) = delete;
    base &operator=(const base &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
