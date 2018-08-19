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

#ifndef MOV_DR_INTEL_X64_EAPIS_H
#define MOV_DR_INTEL_X64_EAPIS_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;

/// MOV DR
///
/// Provides an interface for registering handlers for mov-dr exits.
///
class EXPORT_EAPIS_HVE mov_dr_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by control_register::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Value (in/out)
        ///
        /// For in, the value written by the guest.
        /// default: base::emulate_rdgpr
        ///
        /// For out, the value written to vmcs_n::guest_dr7
        /// default: (base::emulate_rdgpr & 0xFFFFFFFF)
        ///
        uint64_t val;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state with the value
        /// from the default.
        ///
        /// default: false
        ///
        bool ignore_write;

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
    /// @param apis the apis object for this mov-dr handler
    ///
    mov_dr_handler(gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mov_dr_handler() final;

public:

    /// Add Write DR7 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

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
        uint64_t val;
    };

    std::list<record_t> m_log;

public:

    /// @cond

    mov_dr_handler(mov_dr_handler &&) = default;
    mov_dr_handler &operator=(mov_dr_handler &&) = default;

    mov_dr_handler(const mov_dr_handler &) = delete;
    mov_dr_handler &operator=(const mov_dr_handler &) = delete;

    /// @endcond
};

}
}

#endif
