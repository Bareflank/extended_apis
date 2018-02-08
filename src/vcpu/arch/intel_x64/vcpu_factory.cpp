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

#include <bftypes.h>
#include <bfdelegate.h>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/vcpu/arch/intel_x64/vcpu.h>

#include "../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../../include/hve/arch/intel_x64/vmcs/vmcs_vmm_state.h"
#include "../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"

using eapis_vmcs = eapis::intel_x64::vmcs::vmcs;
using eapis_vmm_state = eapis::intel_x64::vmcs::vmcs_state_vmm;
using eapis_exit_handler = eapis::intel_x64::exit_handler::exit_handler;

std::unique_ptr<bfvmm::vcpu>
bfvmm::vcpu_factory::make_vcpu(vcpuid::type vcpuid, user_data *data)
{
    bfignored(data);

    auto vmcs = std::make_unique<eapis_vmcs>();
    auto vmm_state = std::make_unique<eapis_vmm_state>();
    auto exit_handler = std::make_unique<eapis_exit_handler>();

    return std::make_unique<bfvmm::intel_x64::vcpu>(
               vcpuid,
               nullptr,                         // default vmxon
               std::move(vmcs),
               std::move(exit_handler),
               std::move(vmm_state),
               nullptr);                        // default guest_state
}
