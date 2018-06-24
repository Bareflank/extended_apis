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
#include "../../../hve/arch/intel_x64/vic.h"
#include "../../../hve/arch/intel_x64/ept/memory_map.h"

namespace eapis
{
namespace intel_x64
{

/// vcpu
///
/// Manages the lifetime of the exit handlers created upon construction.
/// This class serves as the root from which all other resources may be
/// accesses, e.g. the vmcs and exit_handler.
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

    /// Get VIC (virtual interrupt controller)
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the vic object stored in this vCPU
    ///
    gsl::not_null<eapis::intel_x64::vic *> vic();

    /// Get EMM (EPT memory map)
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the emm object stored in this vCPU
    ///
    gsl::not_null<eapis::intel_x64::ept::memory_map *> emm();

    /// Add handlers for booting OS from EFI
    ///
    /// @expects
    /// @ensures
    ///
    void add_efi_handlers();

private:

    /// Handlers for booting OS from EFI
    ///
    /// @expects
    /// @ensures
    ///
    bool efi_handle_cpuid(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_rdmsr(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_wrmsr(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);
    bool efi_handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info);
    bool efi_handle_vmcall(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_init_signal(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_sipi(gsl::not_null<vmcs_t *> vmcs);
    bool efi_handle_pause(gsl::not_null<vmcs_t *> vmcs);

    std::unique_ptr<eapis::intel_x64::ept::memory_map> m_emm;
    std::unique_ptr<eapis::intel_x64::hve> m_hve;
    std::unique_ptr<eapis::intel_x64::vic> m_vic;

    uint64_t m_sipi_count{0};
};

}
}

#endif
