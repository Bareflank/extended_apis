//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
