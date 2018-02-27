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

#include <bfvmm/vcpu/arch/intel_x64/vcpu.h>

#include "../../../hve/arch/intel_x64/cpuid.h"
#include "../../../hve/arch/intel_x64/crs.h"
#include "../../../hve/arch/intel_x64/drs.h"
#include "../../../hve/arch/intel_x64/msrs.h"
#include "../../../hve/arch/intel_x64/vpid.h"

namespace eapis
{
namespace intel_x64
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

public:

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Enable CPUID Trapping
    ///
    /// @expects
    /// @ensures
    ///
    void enable_cpuid_trapping()
    { m_cpuid = std::make_unique<eapis::intel_x64::cpuid>(this->exit_handler()); }

    /// Get CPUID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CPUID object stored in the vCPU if CPUID trapping is
    ///     enabled, otherwise a nullptr is returned.
    ///
    auto *cpuid()
    { return m_cpuid.get(); }

    //--------------------------------------------------------------------------
    // CRs
    //--------------------------------------------------------------------------

    /// Enable CR Trapping
    ///
    /// @expects
    /// @ensures
    ///
    void enable_cr_trapping()
    { m_crs = std::make_unique<eapis::intel_x64::crs>(this->exit_handler()); }

    /// Get CR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the CR object stored in the vCPU if CR trapping is
    ///     enabled, otherwise a nullptr is returned.
    ///
    auto *crs()
    { return m_crs.get(); }

    //--------------------------------------------------------------------------
    // DRs
    //--------------------------------------------------------------------------

    /// Enable DR Trapping
    ///
    /// @expects
    /// @ensures
    ///
    void enable_dr_trapping()
    { m_drs = std::make_unique<eapis::intel_x64::drs>(this->exit_handler()); }

    /// Get DR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the DR object stored in the vCPU if DR trapping is
    ///     enabled, otherwise a nullptr is returned.
    ///
    auto *drs()
    { return m_drs.get(); }

    //--------------------------------------------------------------------------
    // MSRs
    //--------------------------------------------------------------------------

    /// Enable MSR Trapping
    ///
    /// @expects
    /// @ensures
    ///
    void enable_msr_trapping()
    { m_msrs = std::make_unique<eapis::intel_x64::msrs>(this->exit_handler()); }

    /// Get MSR Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the MSR object stored in the vCPU if MSR trapping is
    ///     enabled, otherwise a nullptr is returned.
    ///
    auto *msrs()
    { return m_msrs.get(); }

    //--------------------------------------------------------------------------
    // VPID
    //--------------------------------------------------------------------------

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    void enable_vpid(uint16_t id)
    { m_vpid = std::make_unique<eapis::intel_x64::vpid>(id); }

    /// Get VPID Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VPID object stored in the vCPU if VPID trapping is
    ///     enabled, otherwise a nullptr is returned.
    ///
    auto *vpid()
    { return m_vpid.get(); }

private:

    std::unique_ptr<eapis::intel_x64::cpuid> m_cpuid;
    std::unique_ptr<eapis::intel_x64::crs> m_crs;
    std::unique_ptr<eapis::intel_x64::drs> m_drs;
    std::unique_ptr<eapis::intel_x64::msrs> m_msrs;
    std::unique_ptr<eapis::intel_x64::vpid> m_vpid;
};

}
}
