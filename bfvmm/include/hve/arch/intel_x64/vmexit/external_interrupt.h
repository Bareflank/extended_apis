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

/// External interrupt
///
/// Provides an interface for registering handlers for external-interrupt
/// exits.
///
class EXPORT_EAPIS_HVE external_interrupt_handler
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
        delegate<bool(gsl::not_null<vcpu_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this external-interrupt handler
    ///
    external_interrupt_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
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

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    external_interrupt_handler(external_interrupt_handler &&) = default;
    external_interrupt_handler &operator=(external_interrupt_handler &&) = default;

    external_interrupt_handler(const external_interrupt_handler &) = delete;
    external_interrupt_handler &operator=(const external_interrupt_handler &) = delete;

    /// @endcond
};

}

#endif
