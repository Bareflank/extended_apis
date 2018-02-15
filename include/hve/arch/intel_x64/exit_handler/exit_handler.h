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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_H

#include <bfgsl.h>

#include <deque>
#include <list>
#include <vector>
#include <functional>

#include "../../../../hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../../hve/arch/intel_x64/exit_handler/exit_handler.h"

#include <intrinsics.h>

#include <bfvmm/memory_manager/object_allocator.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>

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

/// Exit Handler (EAPIS)
///
/// Provides the exit handler needed by the EAPIS. This is intended to be
/// subclassed, and certain functions need to be handled based on how the
/// VMCS is setup.
///
class EXPORT_EAPIS_HVE exit_handler
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    exit_handler(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exit_handler() = default;


    bfvmm::intel_x64::vmcs *m_vmcs;

public:

    /// @cond

    exit_handler(exit_handler &&) = default;
    exit_handler &operator=(exit_handler &&) = default;

    exit_handler(const exit_handler &) = delete;
    exit_handler &operator=(const exit_handler &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
