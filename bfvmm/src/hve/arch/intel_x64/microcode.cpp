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

#include <bfdebug.h>
#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

static bool
ia32_bios_updt_trig__rdmsr_handler(
    gsl::not_null<vmcs_t *> vmcs, rdmsr_handler::info_t &info)
{
    bfignored(vmcs);

    info.val = 0;
    return true;
}

static bool
ia32_bios_updt_trig__wrmsr_handler(
    gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_write = true;
    return true;
}

static bool
ia32_bios_sign_id__rdmsr_handler(
    gsl::not_null<vmcs_t *> vmcs, rdmsr_handler::info_t &info)
{
    bfignored(vmcs);

    // QUIRK
    //
    // The Intel SDM states that VMMs should return 0 to ignore
    // a microcode update, but the Linux kernel doesn't seem to
    // respect this on the APs (for some reason the BSP is fine)
    // and as a result, the APs end up in an endless loop. To
    // prevent this, we return all Fs, and as a result, the Linux
    // kernel thinks that a better version of the microcode is
    // already present.

    info.val = 0xFFFFFFFFFFFFFFFF;
    return true;
}

static bool
ia32_bios_sign_id__wrmsr_handler(
    gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
{
    bfignored(vmcs);

    info.ignore_write = true;
    return true;
}

microcode_handler::microcode_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state)
{
    using namespace vmcs_n;
    bfignored(eapis_vcpu_global_state);

    apis->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_bios_updt_trig::addr,
        rdmsr_handler::handler_delegate_t::create<ia32_bios_updt_trig__rdmsr_handler>()
    );

    apis->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_bios_updt_trig::addr,
        wrmsr_handler::handler_delegate_t::create<ia32_bios_updt_trig__wrmsr_handler>()
    );

    apis->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_bios_sign_id::addr,
        rdmsr_handler::handler_delegate_t::create<ia32_bios_sign_id__rdmsr_handler>()
    );

    apis->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_bios_sign_id::addr,
        wrmsr_handler::handler_delegate_t::create<ia32_bios_sign_id__wrmsr_handler>()
    );
}

}
}
