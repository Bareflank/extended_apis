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

#include <bfvmm/hve/arch/intel_x64/vcpu/vcpu.h>

#include "../../../hve/arch/intel_x64/hve.h"

namespace eapis
{
namespace intel_x64
{

class vcpu : public bfvmm::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vcpu(vcpuid::type id);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Get HVE (hardware virtualization extensions)
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the hve object stored in this vCPU
    ///
    gsl::not_null<eapis::intel_x64::hve *> hve();

private:

    /// @cond

    std::unique_ptr<eapis::intel_x64::hve> m_hve;

    /// @endcond
};

}
}

#endif
