//
// Bareflank Hypervisor
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

#ifndef VMCS_INTEL_X64_VMM_STATE_EAPIS_H
#define VMCS_INTEL_X64_VMM_STATE_EAPIS_H

#include <hve/arch/intel_x64/vmcs/vmcs_state_vmm.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_VMCS
#ifdef SHARED_EAPIS_VMCS
#define EXPORT_EAPIS_VMCS EXPORT_SYM
#else
#define EXPORT_EAPIS_VMCS IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_VMCS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// VMM Intel x64 State (EAPIs)
///
/// The following defines the state class for the VMM. The default VMM state
/// is used here except the constructor, were EAPI specific resources are
/// initialized.
///
class EXPORT_EAPIS_VMCS vmcs_intel_x64_vmm_state_eapis :
    public vmcs_intel_x64_vmm_state
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64_vmm_state_eapis();

    /// Default Destructor
    ///
    ~vmcs_intel_x64_vmm_state_eapis() override = default;

public:

    /// @cond

    vmcs_intel_x64_vmm_state_eapis(vmcs_intel_x64_vmm_state_eapis &&) noexcept = delete;
    vmcs_intel_x64_vmm_state_eapis &operator=(vmcs_intel_x64_vmm_state_eapis &&) noexcept = delete;

    vmcs_intel_x64_vmm_state_eapis(const vmcs_intel_x64_vmm_state_eapis &) = delete;
    vmcs_intel_x64_vmm_state_eapis &operator=(const vmcs_intel_x64_vmm_state_eapis &) = delete;

    /// @endcond
};

#endif
