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

#ifndef SIPI_SIGNAL_INTEL_X64_EAPIS_H
#define SIPI_SIGNAL_INTEL_X64_EAPIS_H

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

/// SIPI handler
///
/// Provides an interface for registering handlers of SIPI exits
///
class EXPORT_EAPIS_HVE sipi_signal_handler : public base
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this sipi handler
    /// @param eapis_vcpu_global_state a pointer to the vCPUs global state
    ///
    sipi_signal_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~sipi_signal_handler() final = default;

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

public:

    /// @cond

    sipi_signal_handler(sipi_signal_handler &&) = default;
    sipi_signal_handler &operator=(sipi_signal_handler &&) = default;

    sipi_signal_handler(const sipi_signal_handler &) = delete;
    sipi_signal_handler &operator=(const sipi_signal_handler &) = delete;

    /// @endcond
};

}
}

#endif
