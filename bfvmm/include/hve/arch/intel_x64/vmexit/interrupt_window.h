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

#ifndef INTERRUPT_WINDOW_INTEL_X64_EAPIS_H
#define INTERRUPT_WINDOW_INTEL_X64_EAPIS_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;

/// Interrupt window
///
/// Provides an interface for registering handlers of the interrupt-window exit.
///
class EXPORT_EAPIS_HVE interrupt_window_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by external_interrupt_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Ignore disable (out)
        ///
        /// If true, do not update the guest's register state with the value
        /// from the default base::emulation_wrgpr. Set this to true if your
        /// handler returns true and has already update the guest register
        /// state.
        ///
        /// default: false
        ///
        bool ignore_disable{false};
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
    /// @param apis the apis object for this interrupt window handler
    ///
    interrupt_window_handler(gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_window_handler() final = default;

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
    /// @expects
    /// @ensures
    ///
    void enable_exiting();

    /// Disable exiting
    ///
    /// @expects
    /// @ensures
    ///
    void disable_exiting();

    /// Is open
    ///
    /// @expects
    /// @ensures
    ///
    /// @return true iff the external interrupt window is open
    ///
    bool is_open();

    /// Inject
    ///
    /// Inject an external interrupt at the given vector on the upcoming
    /// VM-entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    ///
    void inject(uint64_t vector);

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
    void dump_log() final
    { }

public:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    interrupt_window_handler(interrupt_window_handler &&) = default;
    interrupt_window_handler &operator=(interrupt_window_handler &&) = default;

    interrupt_window_handler(const interrupt_window_handler &) = delete;
    interrupt_window_handler &operator=(const interrupt_window_handler &) = delete;

    /// @endcond
};

}
}

#endif
