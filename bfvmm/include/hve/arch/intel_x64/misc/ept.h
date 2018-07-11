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

#ifndef EAPIS_EPT_HANDLER_INTEL_X64_H
#define EAPIS_EPT_HANDLER_INTEL_X64_H

#include "ept/mmap.h"
#include "ept/helpers.h"

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

/// EPT
///
/// Provides an interface for enabling EPT
///
class EXPORT_EAPIS_HVE ept_handler
{
    bool m_enabled{false};

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    ept_handler();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_handler() = default;

    /// Set EPTP
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map A pointer to the map to set EPTP to. If the pointer is
    ///     a nullptr, EPT is disabled.
    ///
    void set_eptp(ept::mmap *map);

public:

    /// @cond

    ept_handler(ept_handler &&) = default;
    ept_handler &operator=(ept_handler &&) = default;

    ept_handler(const ept_handler &) = delete;
    ept_handler &operator=(const ept_handler &) = delete;

    /// @endcond
};

}
}

#endif
