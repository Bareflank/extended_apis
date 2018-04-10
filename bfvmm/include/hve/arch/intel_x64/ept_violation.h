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

#ifndef EPT_VIOLATION_INTEL_X64_H
#define EPT_VIOLATION_INTEL_X64_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class hve;

/// EPT Violation
///
/// Provides an interface for registering handlers for EPT violation
/// exits.
///
class EXPORT_EAPIS_HVE ept_violation : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by ept_violation::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// GVA (in)
        ///
        /// The guest virtual (linear) address that caused the exit
        ///
        uint64_t gva;

        /// GPA (in)
        ///
        /// The guest physical address that caused the exit
        ///
        uint64_t gpa;

        /// Exit qualification (in)
        ///
        /// The VMCS exit qualification that caused the exit
        ///
        uint64_t exit_qualification;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
        ///
        bool ignore_advance;
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object for this EPT violation handler
    ///
    ept_violation(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_violation() final;

public:

    /// Add Read EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_read_handler(handler_delegate_t &&d);

    /// Add Write EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_write_handler(handler_delegate_t &&d);

    /// Add Execute EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_execute_handler(handler_delegate_t &&d);

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
    void dump_log() final;

private:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    bool handle_read(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    bool handle_write(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    bool handle_execute(gsl::not_null<vmcs_t *> vmcs, info_t &info);

    /// @endcond

private:

    gsl::not_null<exit_handler_t *> m_exit_handler;

    std::list<handler_delegate_t> m_read_handlers;
    std::list<handler_delegate_t> m_write_handlers;
    std::list<handler_delegate_t> m_execute_handlers;

private:

    struct record_t {
        uint64_t gva;
        uint64_t gpa;
    };

    std::list<record_t> m_log;

public:

    /// @cond

    ept_violation(ept_violation &&) = default;
    ept_violation &operator=(ept_violation &&) = default;

    ept_violation(const ept_violation &) = delete;
    ept_violation &operator=(const ept_violation &) = delete;

    /// @endcond
};

}
}

#endif
