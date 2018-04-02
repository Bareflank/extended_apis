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

/// VPID
///
/// Provides an interface for enabling VPID
///
class EXPORT_EAPIS_HVE vpid
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vpid();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vpid() = default;

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

private:

    vmcs_n::value_type m_id;

public:

    /// @cond

    vpid(vpid &&) = default;
    vpid &operator=(vpid &&) = default;

    vpid(const vpid &) = delete;
    vpid &operator=(const vpid &) = delete;

    /// @endcond
};

}
}

#endif
