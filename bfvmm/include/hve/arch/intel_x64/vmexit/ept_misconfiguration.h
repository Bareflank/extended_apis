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

#ifndef EPT_MISCONFIGURATION_INTEL_X64_H
#define EPT_MISCONFIGURATION_INTEL_X64_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;
class eapis_vcpu_global_state_t;

/// EPT Misconfiguration
///
/// Provides an interface for registering handlers for EPT misconfiguration
/// exits.
///
class EXPORT_EAPIS_HVE ept_misconfiguration_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by ept_misconfiguration_handler::handle before being
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
    /// @param apis the apis object for this EPT misconfiguration handler
    /// @param eapis_vcpu_global_state a pointer to the vCPUs global state
    ///
    ept_misconfiguration_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_misconfiguration_handler() final;

public:

    /// Add EPT Misconfiguration Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

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

public:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    std::list<handler_delegate_t> m_handlers;

private:

    struct record_t {
        uint64_t gva;
        uint64_t gpa;
    };

    std::list<record_t> m_log;

public:

    /// @cond

    ept_misconfiguration_handler(ept_misconfiguration_handler &&) = default;
    ept_misconfiguration_handler &operator=(ept_misconfiguration_handler &&) = default;

    ept_misconfiguration_handler(const ept_misconfiguration_handler &) = delete;
    ept_misconfiguration_handler &operator=(const ept_misconfiguration_handler &) = delete;

    /// @endcond
};

}
}

#endif
