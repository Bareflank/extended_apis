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

#include <list>

#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>

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

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis::intel_x64
{

class vcpu;

/// EPT Violation
///
/// Provides an interface for registering handlers for EPT violation
/// exits.
///
class EXPORT_EAPIS_HVE ept_violation_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by ept_violation_handler::handle before being
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
        delegate<bool(gsl::not_null<vcpu_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this EPT violation handler
    ///
    ept_violation_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_violation_handler() = default;

public:

    /// Add Read EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_read_handler(const handler_delegate_t &d);

    /// Add Write EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_write_handler(const handler_delegate_t &d);

    /// Add Execute EPT Violation Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_execute_handler(const handler_delegate_t &d);

    /// Add Default Read Handler
    ///
    /// This is called when no registered handlers have been called and
    /// the internal implementation is needed. Note that this function
    /// can still return false and let the internal implementation pass
    /// the instruction through
    ///
    /// Also note that the handler registered here is a base exit handler
    /// delegate. The info structure is not passed, and therefor,
    /// no emulation is provided to this handler.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void set_default_read_handler(const ::handler_delegate_t &d);

    /// Add Default Write Handler
    ///
    /// This is called when no registered handlers have been called and
    /// the internal implementation is needed. Note that this function
    /// can still return false and let the internal implementation pass
    /// the instruction through
    ///
    /// Also note that the handler registered here is a base exit handler
    /// delegate. The info structure is not passed, and therefor,
    /// no emulation is provided to this handler.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void set_default_write_handler(const ::handler_delegate_t &d);

    /// Add Default Execute Handler
    ///
    /// This is called when no registered handlers have been called and
    /// the internal implementation is needed. Note that this function
    /// can still return false and let the internal implementation pass
    /// the instruction through
    ///
    /// Also note that the handler registered here is a base exit handler
    /// delegate. The info structure is not passed, and therefor,
    /// no emulation is provided to this handler.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void set_default_execute_handler(const ::handler_delegate_t &d);

public:

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    bool handle_read(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_write(gsl::not_null<vcpu_t *> vcpu, info_t &info);
    bool handle_execute(gsl::not_null<vcpu_t *> vcpu, info_t &info);

private:

    vcpu *m_vcpu;

    ::handler_delegate_t m_default_read_handler;
    ::handler_delegate_t m_default_write_handler;
    ::handler_delegate_t m_default_execute_handler;

    std::list<handler_delegate_t> m_read_handlers;
    std::list<handler_delegate_t> m_write_handlers;
    std::list<handler_delegate_t> m_execute_handlers;

public:

    /// @cond

    ept_violation_handler(ept_violation_handler &&) = default;
    ept_violation_handler &operator=(ept_violation_handler &&) = default;

    ept_violation_handler(const ept_violation_handler &) = delete;
    ept_violation_handler &operator=(const ept_violation_handler &) = delete;

    /// @endcond
};

}

#endif
