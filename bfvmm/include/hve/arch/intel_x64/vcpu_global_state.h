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

#ifndef VCPU_GLOBAL_STATE_INTEL_X64_EAPIS_H
#define VCPU_GLOBAL_STATE_INTEL_X64_EAPIS_H

#include <intrinsics.h>

namespace eapis::intel_x64
{

/// VM Global State
///
/// The APIs require global variables that "group" up vcpus into VMs.
/// This allows vcpus to be grouped up into logical VMs that share a
/// common global state.
///
struct vcpu_global_state_t {

    /// Init Called
    ///
    /// Synchronization flag used during the INIT/SIPI process. Specifically
    /// this is used to ensure SIPI is not sent before INIT is finished.
    ///
    std::atomic<bool> init_called{false};

    /// CR0 Fixed Bits
    ///
    /// Defines the bits that must be fixed to 1. Note that these could change
    /// depending on how the system is configured.
    ///
    uint64_t ia32_vmx_cr0_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get()
    };

    /// CR4 Fixed Bits
    ///
    /// Defines the bits that must be fixed to 1. Note that these could change
    /// depending on how the system is configured.
    ///
    uint64_t ia32_vmx_cr4_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get()
    };
};

/// VM Global State Instance
///
/// The default global state. This is needed for host vCPUs. Guest vCPUs
/// need to create and store an instance for each guest VM.
///
inline vcpu_global_state_t g_vcpu_global_state;

}

#endif
