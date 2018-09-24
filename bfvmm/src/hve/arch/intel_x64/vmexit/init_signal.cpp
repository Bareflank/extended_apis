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

#include <hve/arch/intel_x64/vcpu.h>

namespace eapis::intel_x64
{

init_signal_handler::init_signal_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::init_signal,
        ::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle>(this)
    );

    // TODO:
    //
    // Disable this once we have booted. We only need to monitor this until
    // it is written. Once it is written, we can turn thus off. If we don't
    // a crap load of exits occur that do nothing. Also, this
    // needs to be updated to support the xAPIC instead of the x2APIC
    //
    // vcpu->add_wrmsr_handler(
    //     ::intel_x64::msrs::ia32_x2apic_icr::addr,
    //     wrmsr_handler::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle_icr_write>(this)
    // );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
init_signal_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    using namespace vmcs_n::guest_activity_state;
    using namespace vmcs_n::vm_entry_controls;

    bfignored(vcpu);

    // TODO:
    //
    // - Currently, there are several registers that the VMCS does not control
    //   and that we are not saving in our save state that we are not resetting
    //   here. For completness, we should find a way to reset all of the
    //   registers outlined by the SDM. These registers include:
    //   - CR2
    //   - x87 FPU Control Word
    //   - x87 FPU Status Word
    //   - x87 FPU Tag Word
    //   - x87 FPU Data Operand
    //   - dr0, dr1, dr2, dr3
    //   - dr6
    //   = IA32_XSS
    //   - BNDCFGU
    //   - BND0-BND3
    //   - IA32_BNDCFGS
    //
    // - Currently, we don't set the Extended Model Value in EDX, whish is
    //   stated by the SDM. We use 0x600, which seems to work fine, but
    //   at some point, we should fill in the proper value
    //

    vmcs_n::guest_rflags::set(0x00000002);
    vcpu->set_rip(0x0000FFF0);

    vmcs_n::guest_cr0::set(0x60000010 | m_vcpu->global_state()->ia32_vmx_cr0_fixed0);
    vmcs_n::guest_cr3::set(0);
    vmcs_n::guest_cr4::set(0x00000000 | m_vcpu->global_state()->ia32_vmx_cr4_fixed0);

    vmcs_n::cr0_read_shadow::set(0x60000010);
    vmcs_n::cr4_read_shadow::set(0);

    vmcs_n::guest_cs_selector::set(0xF000);
    vmcs_n::guest_cs_base::set(0xFFFF0000);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs_n::guest_ss_selector::set(0);
    vmcs_n::guest_ss_base::set(0);
    vmcs_n::guest_ss_limit::set(0xFFFF);
    vmcs_n::guest_ss_access_rights::set(0x93);

    vmcs_n::guest_ds_selector::set(0);
    vmcs_n::guest_ds_base::set(0);
    vmcs_n::guest_ds_limit::set(0xFFFF);
    vmcs_n::guest_ds_access_rights::set(0x93);

    vmcs_n::guest_es_selector::set(0);
    vmcs_n::guest_es_base::set(0);
    vmcs_n::guest_es_limit::set(0xFFFF);
    vmcs_n::guest_es_access_rights::set(0x93);

    vmcs_n::guest_fs_selector::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_fs_limit::set(0xFFFF);
    vmcs_n::guest_fs_access_rights::set(0x93);

    vmcs_n::guest_gs_selector::set(0);
    vmcs_n::guest_gs_base::set(0);
    vmcs_n::guest_gs_limit::set(0xFFFF);
    vmcs_n::guest_gs_access_rights::set(0x93);

    vcpu->set_rdx(0x00000600);
    vcpu->set_rax(0);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rsi(0);
    vcpu->set_rdi(0);
    vcpu->set_rbp(0);
    vcpu->set_rsp(0);

    vmcs_n::guest_gdtr_base::set(0);
    vmcs_n::guest_gdtr_limit::set(0xFFFF);

    vmcs_n::guest_idtr_base::set(0);
    vmcs_n::guest_idtr_limit::set(0xFFFF);

    vmcs_n::guest_ldtr_selector::set(0);
    vmcs_n::guest_ldtr_base::set(0);
    vmcs_n::guest_ldtr_limit::set(0xFFFF);
    vmcs_n::guest_ldtr_access_rights::set(0x82);

    vmcs_n::guest_tr_selector::set(0);
    vmcs_n::guest_tr_base::set(0);
    vmcs_n::guest_tr_limit::set(0xFFFF);
    vmcs_n::guest_tr_access_rights::set(0x8B);

    vmcs_n::guest_dr7::set(0x00000400);

    vcpu->set_r08(0);
    vcpu->set_r09(0);
    vcpu->set_r10(0);
    vcpu->set_r11(0);
    vcpu->set_r12(0);
    vcpu->set_r13(0);
    vcpu->set_r14(0);
    vcpu->set_r15(0);

    vmcs_n::guest_ia32_efer::set(0);
    vmcs_n::guest_fs_base::set(0);
    vmcs_n::guest_gs_base::set(0);

    // .........................................................................
    // VT-x Specific
    // .........................................................................

    // The following code is specific to VT-x. Typically the hardware would
    // turn off 64bit mode and set the activity state, but we need to do this
    // ourselves instead.

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::wait_for_sipi
    );

    ia_32e_mode_guest::disable();

    // .........................................................................
    // Done
    // .........................................................................

    return (m_vcpu->global_state()->init_called = true);
}

bool
init_signal_handler::handle_init_assert(
    gsl::not_null<vcpu_t *> vcpu, wrmsr_handler::info_t &info)
{
    using namespace ::intel_x64::msrs;
    bfignored(vcpu);

    m_vcpu->global_state()->init_called = false;

    ::intel_x64::msrs::set(
        ia32_x2apic_icr::addr, info.val
    );

    ::intel_x64::spin_until_true(m_vcpu->global_state()->init_called);
    m_vcpu->global_state()->init_called = false;

    return (info.ignore_write = true);
}

bool
init_signal_handler::handle_init_deassert(
    gsl::not_null<vcpu_t *> vcpu, wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    // Note
    //
    // We consume the deassert as it is not needed, and potentially
    // over complicates the INIT/SIPI process
    //

    return (info.ignore_write = true);
}

bool
init_signal_handler::handle_icr_write(
    gsl::not_null<vcpu_t *> vcpu, wrmsr_handler::info_t &info)
{
    using namespace ::intel_x64::lapic;

    if (icr::delivery_mode::get(info.val) != icr::delivery_mode::init) {
        return false;
    }

    if (icr::level::is_enabled(info.val)) {
        return handle_init_assert(vcpu, info);
    }
    else {
        return handle_init_deassert(vcpu, info);
    }
}

}
