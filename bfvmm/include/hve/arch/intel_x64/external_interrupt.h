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

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class hve;

class EXPORT_EAPIS_HVE external_interrupt : public base
{
public:

    struct info_t {
        uint64_t vector;        // In
    };

    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    external_interrupt(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt() final;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(
        vmcs_n::value_type vector, handler_delegate_t &&d);

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

    /// @cond

    void enable_exiting();

    /// @endcond

    std::array<std::list<handler_delegate_t>, 256> m_handlers;
    std::array<uint64_t, 256> m_log;

public:

    /// @cond

    external_interrupt(external_interrupt &&) = default;
    external_interrupt &operator=(external_interrupt &&) = default;

    external_interrupt(const external_interrupt &) = delete;
    external_interrupt &operator=(const external_interrupt &) = delete;

    /// @endcond
};

}
}

#endif
