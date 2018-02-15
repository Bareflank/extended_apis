//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_EAPIS_H
#define VMCS_INTEL_X64_EAPIS_H

#include <bfgsl.h>
#include <bfvcpuid.h>

#include <vector>
#include <memory>

#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>

#include <arch/x64/misc.h>
#include <arch/x64/msrs.h>
#include <arch/x64/portio.h>

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace eapis
{
namespace intel_x64
{

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

// WARNING:
//
// All of these APIs operate on the currently loaded VMCS, as well as on
// private members. If the currently loaded VMCS is not "this" vmcs,
// corruption is almost certain. We _do not_ check to make sure that this case
// is not possible because it would cost far too much to check the currently
// loaded VMCS on every operation. Thus, the user should take great care to
// ensure that these APIs are used on the currently loaded VMCS. If this is
// not the case, run vmcs->load() first to ensure the right VMCS is being
// used.
//

/// VMCS (EAPIs)
///
/// Defines the EAPIs version of the VMCS. Note that this is intended to be
/// subclassed.
///
class EXPORT_EAPIS_HVE vmcs
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vmcs();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcs() = default;

    /// @cond

    vmcs(vmcs &&) = default;
    vmcs &operator=(vmcs &&) = default;

    vmcs(const vmcs &) = delete;
    vmcs &operator=(const vmcs &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
