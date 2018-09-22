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

#ifndef VPID_INTEL_X64_EAPIS_H
#define VPID_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class apis;
class eapis_vcpu_global_state_t;

/// VPID
///
/// Provides an interface for enabling VPID
///
class EXPORT_EAPIS_HVE vpid_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this rdmsr handler
    /// @param eapis_vcpu_global_state a pointer to the vCPUs global state
    ///
    vpid_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vpid_handler() = default;

    /// Get ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID
    ///
    vmcs_n::value_type id() const noexcept;

    /// Enable
    ///
    /// @expects
    /// @ensures
    ///
    void enable();

    /// Disable
    ///
    /// @expects
    /// @ensures
    ///
    void disable();

private:

    vmcs_n::value_type m_id;

public:

    /// @cond

    vpid_handler(vpid_handler &&) = default;
    vpid_handler &operator=(vpid_handler &&) = default;

    vpid_handler(const vpid_handler &) = delete;
    vpid_handler &operator=(const vpid_handler &) = delete;

    /// @endcond
};

}
}

#endif
