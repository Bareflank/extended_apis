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

#ifndef MICROCODE_INTEL_X64_EAPIS_H
#define MICROCODE_INTEL_X64_EAPIS_H

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

/// Microcode Handler
///
/// Provides an interface for handling microcode updates
///
/// TODO:
///
/// Currently, this only disables microcode updates. In the future, we need to
/// add the the following additional APIs
/// - emulate update: provide the ability to emulate the update process,
///   allowing the OS to update the microcode itself.
/// - load custom microcode: we should also provide the ability to upload your
///   own microcode from the VMM's point of view. This way, you can package
///   your own microcode, or vmcall to load microcode as needed.
///
class EXPORT_EAPIS_HVE microcode_handler : public base
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
    microcode_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~microcode_handler() final = default;

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

    microcode_handler(microcode_handler &&) = default;
    microcode_handler &operator=(microcode_handler &&) = default;

    microcode_handler(const microcode_handler &) = delete;
    microcode_handler &operator=(const microcode_handler &) = delete;

    /// @endcond
};

}
}

#endif
