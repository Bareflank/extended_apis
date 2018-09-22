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

#ifndef INIT_SIGNAL_INTEL_X64_EAPIS_H
#define INIT_SIGNAL_INTEL_X64_EAPIS_H

#include "wrmsr.h"
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

/// INIT signal
///
/// Provides an interface for registering handlers of the INIT signal exit.
///
class EXPORT_EAPIS_HVE init_signal_handler : public base
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this INIT signal handler
    /// @param eapis_vcpu_global_state a pointer to the vCPUs global state
    ///
    init_signal_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~init_signal_handler() final = default;

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

    gsl::not_null<eapis_vcpu_global_state_t *> m_eapis_vcpu_global_state;

    bool handle_init_assert(
        gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);
    bool handle_init_deassert(
        gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);
    bool handle_icr_write(
        gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info);

public:

    /// @cond

    init_signal_handler(init_signal_handler &&) = default;
    init_signal_handler &operator=(init_signal_handler &&) = default;

    init_signal_handler(const init_signal_handler &) = delete;
    init_signal_handler &operator=(const init_signal_handler &) = delete;

    /// @endcond
};

}
}

#endif
