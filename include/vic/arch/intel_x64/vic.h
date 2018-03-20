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

#ifndef VIC_INTEL_X64_EAPIS_H
#define VIC_INTEL_X64_EAPIS_H

#include "interrupt_manager.h"

namespace eapis
{
namespace intel_x64
{

class vic
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vic(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vic() = default;

public:

    /// Get HVE Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the hve object stored in this vic
    ///
    gsl::not_null<eapis::intel_x64::hve *> hve();

    /// Get Interrupt Manager Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the interrupt manager object stored in the vic
    ///
    gsl::not_null<eapis::intel_x64::interrupt_manager *> interrupt_manager();

    /// Add interrupt handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector the handler handles
    /// @param d the interrupt handler delegate
    ///
    void add_interrupt_handler(
        uint64_t vector, interrupt_manager::handler_delegate_t &&d
    );

private:

    /// @cond

    eapis::intel_x64::hve *m_hve;
    std::unique_ptr<eapis::intel_x64::interrupt_manager> m_interrupt_manager;

    /// @endcond
};

}
}

#endif
