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

#ifndef EXTERNAL_INTERRUPT_INTEL_X64_EAPIS_H
#define EXTERNAL_INTERRUPT_INTEL_X64_EAPIS_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;

/// External interrupt
///
/// Provides an interface for registering handlers for external-interrupt
/// exits.
///
class EXPORT_EAPIS_HVE external_interrupt_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by external_interrupt_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Vector (in)
        ///
        /// The vector that caused the exit
        ///
        /// default: vmcs_n::vm_exit_interruption_information::vector
        ///
        uint64_t vector{0};
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
    /// @param apis the apis object for this external-interrupt handler
    ///
    external_interrupt_handler(gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt_handler() final;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

    /// Enable exiting
    ///
    /// Example:
    /// @code
    /// this->enable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_exiting();

    /// Disable exiting
    ///
    /// Example:
    /// @code
    /// this->disable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_exiting();

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

    std::array<uint64_t, 256> m_log{};

public:

    /// @cond

    external_interrupt_handler(external_interrupt_handler &&) = default;
    external_interrupt_handler &operator=(external_interrupt_handler &&) = default;

    external_interrupt_handler(const external_interrupt_handler &) = delete;
    external_interrupt_handler &operator=(const external_interrupt_handler &) = delete;

    /// @endcond
};

}
}

#endif
