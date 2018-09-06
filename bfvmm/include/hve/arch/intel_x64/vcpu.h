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

#ifndef VCPU_INTEL_X64_EAPIS_H
#define VCPU_INTEL_X64_EAPIS_H

#include "apis.h"
#include <bfvmm/hve/arch/intel_x64/vcpu/vcpu.h>

namespace eapis
{
namespace intel_x64
{

/// vCPU
///
class vcpu : public bfvmm::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    /// @param eapis_vcpu_state a pointer to the vCPUs state
    ///
    vcpu(
        vcpuid::type id,
        eapis_vcpu_state_t *eapis_vcpu_state = nullptr
    ) :
        bfvmm::intel_x64::vcpu(id),
        m_apis{
        vmcs(),
        exit_handler(),
        eapis_vcpu_state == nullptr ? & g_eapis_vcpu_state : eapis_vcpu_state
    }
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// APIs
    ///
    /// @expects
    /// @ensures
    ///
    /// @return a pointer to the eapis
    ///
    gsl::not_null<apis *> eapis()
    { return &m_apis; }

private:

    eapis::intel_x64::apis m_apis;
};

}
}

#endif
