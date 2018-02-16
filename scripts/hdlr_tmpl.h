//
// Bareflank Extended APIs
//
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

#ifndef CLASS_INTEL_X64_EAPIS_H
#define CLASS_INTEL_X64_EAPIS_H

#include <bfgsl.h>
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

/// CLASS
///
///
class EXPORT_EAPIS_HVE CLASS
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    CLASS();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~CLASS() = default;

    /// @cond

    CLASS(CLASS &&) = default;
    CLASS &operator=(CLASS &&) = default;

    CLASS(const CLASS &) = delete;
    CLASS &operator=(const CLASS &) = delete;

    /// @endcond
};

} // namespace intel_x64
} // namespace eapis

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
