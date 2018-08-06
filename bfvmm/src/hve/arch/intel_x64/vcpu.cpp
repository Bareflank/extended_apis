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

#include <bfsupport.h>
#include <bfthreadcontext.h>
#include <bfvmm/memory_manager/arch/x64/unique_map.h>

#include <hve/arch/intel_x64/ept/helpers.h>
#include <hve/arch/intel_x64/ept/intrinsics.h>
#include <hve/arch/intel_x64/cpuid.h>
#include <vcpu/arch/intel_x64/vcpu.h>

bool init_done = false;
bool sipi_done = false;

namespace eapis
{
namespace intel_x64
{

void
vcpu::enable_efi()
{
    if (m_emm == nullptr) {
        m_emm = std::make_unique<eapis::intel_x64::ept::memory_map>();
    }

    if (m_vic == nullptr) {
        m_vic = std::make_unique<eapis::intel_x64::vic>(m_hve.get());
    }

    this->add_efi_handlers();

    ::vmcs_n::guest_ia32_perf_global_ctrl::reserved::set(0);
    ept::identity_map(*m_emm, 0, 0x900000000 - 0x1000);
    ept::enable_ept(ept::eptp(*m_emm));
    m_hve->enable_vpid();
}

// -----------------------------------------------------------------------------
// EFI Handlers
// -----------------------------------------------------------------------------

/// This has to be registered through the base exit_handler because the EAPIs
/// cpuid handlers are keyed off of {leaf, subleaf}, but in practice, when
/// firmware calls cpuid, it may not clear out rcx, resulting in random
/// subleaf values. Until the EAPIs can account for this scenario, this
/// function will need bypass the EAPIs cpuid interface.

bool
vcpu::efi_handle_cpuid(gsl::not_null<vmcs_t *> vmcs)
{
    static constexpr uint32_t centaur_base = 0xC0000000;

    if (vmcs->save_state()->rax == 0xBF01 || vmcs->save_state()->rax == 0xBF00) {
        return false;
    }

    auto leaf = vmcs->save_state()->rax;
    auto ret =
        ::x64::cpuid::get(
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
            gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
        );

    vmcs->save_state()->rax = ret.rax;
    vmcs->save_state()->rbx = ret.rbx;
    vmcs->save_state()->rdx = ret.rdx;

    if (leaf == ::intel_x64::cpuid::feature_information::addr) {
        uint64_t setter = ret.rcx;
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::xsave::from);
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::osxsave::from);
        setter = clear_bit(setter, ::intel_x64::cpuid::feature_information::ecx::vmx::from);
        vmcs->save_state()->rcx = setter;

        //TODO: handle MTRR writes
        setter = clear_bit(ret.rdx, ::intel_x64::cpuid::feature_information::edx::mtrr::from);
        vmcs->save_state()->rdx = setter;
    }
    else if ((leaf & centaur_base) == centaur_base) {
        bfalert_nhex(0, "centaur leaf", leaf);
        bfalert_nhex(0, "centaur subleaf", vmcs->save_state()->rcx);
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
        vmcs->save_state()->rdx = 0;
    }
    else if (leaf == ::intel_x64::cpuid::arch_perf_monitoring::addr) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
    }
    else {
        vmcs->save_state()->rcx = ret.rcx;
    }

    return advance(vmcs);
}

/// This handler has to bypass the EAPIs' rdmsr interface because once
/// you register to handle an msr with the rdmsr class, it reads at the
/// given address. But an MSR may or may not be implemented on a
/// given system and if it's not, a GP will be raised.
///
/// It may be reasonable to add these two addresses to the QUIRK'd out ones in
/// emulate_rdmsr since they aren't architectural.
///
bool
vcpu::efi_handle_rdmsr(gsl::not_null<vmcs_t *> vmcs)
{
    static constexpr uint32_t pkg_perf_status = 0x613;
    static constexpr uint32_t dram_energy_status = 0x619;

    const auto msr = vmcs->save_state()->rcx;

    if (msr == pkg_perf_status || msr == dram_energy_status) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rdx = 0;
        return advance(vmcs);
    }

    return false;
}

bool
vcpu::efi_handle_wrmsr_efer(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    if (::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_disabled()) {
        return true;
    }

    if (get_bit(info.val, ::intel_x64::msrs::ia32_efer::lme::from) != 0U) {
        uint64_t s_cr0 = 0;
        ::vmcs_n::guest_cr0::protection_enable::enable(s_cr0);
        ::vmcs_n::guest_cr0::extension_type::enable(s_cr0);
        ::vmcs_n::guest_cr0::numeric_error::enable(s_cr0);
        ::vmcs_n::guest_cr0::write_protect::enable(s_cr0);
        ::vmcs_n::guest_cr0::not_write_through::enable(s_cr0);
        ::vmcs_n::guest_cr0::cache_disable::enable(s_cr0);
        ::vmcs_n::guest_cr0::paging::enable(s_cr0);
        ::vmcs_n::guest_cr0::set(s_cr0);

        ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
        ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        info.val |= ::intel_x64::msrs::ia32_efer::lma::mask;
    }

    return true;
}

bool
vcpu::efi_handle_wrmsr_perf_global_ctrl(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);
    ::vmcs_n::guest_ia32_perf_global_ctrl::reserved::set(info.val, 0);
    return true;
}

bool
vcpu::efi_handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    using namespace ::vmcs_n::exit_qualification::control_register_access;

    // only need access type 0 but eapis doesn't handle
    // these other access types properly when cr0 is emulated
    auto access_type = access_type::get();
    switch (access_type) {
        case access_type::mov_to_cr:
            info.shadow = info.val;
            ::vmcs_n::guest_cr0::extension_type::enable(info.val);
            ::vmcs_n::guest_cr0::numeric_error::enable(info.val);

            if (vmcs_n::guest_cr0::paging::is_disabled(info.val)) {
                ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
                ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();
                ::vmcs_n::guest_ia32_efer::lma::disable();
                ::vmcs_n::guest_ia32_efer::lme::disable();
            }
            else {
                ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
                ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
                ::vmcs_n::guest_ia32_efer::lma::enable();
                ::vmcs_n::guest_ia32_efer::lme::enable();
            }
            return true;

        case access_type::clts:
            ::vmcs_n::guest_cr0::task_switched::disable(info.shadow);
            ::vmcs_n::guest_cr0::task_switched::disable(info.val);
            return true;

        case access_type::lmsw: {
            auto cur = set_bits(::vmcs_n::guest_cr0::get(), source_data::get(), ~0xFFFFULL);
            info.val = set_bits(cur, ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get(), ~0ULL);
            info.shadow = set_bits(info.shadow, source_data::get(), ~0xFFFFULL);
            return true;
        }

        case access_type::mov_from_cr:
        default:
            throw std::runtime_error("efi_handle_wrcr0 invalid access_type " + std::to_string(access_type));
    }
}

bool
vcpu::efi_handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    info.shadow = info.val;
    info.val = set_bits(
                   info.val, ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get(), ~0ULL
               );
    return true;
}

bool
vcpu::efi_handle_init_signal(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::wait_for_sipi);
    init_done = true;
    return true;
}

bool
vcpu::efi_handle_sipi(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    if (!sipi_done) {
        sipi_done = true;
        return true;
    }

    ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();

    ::vmcs_n::value_type cr0 = 0;
    ::vmcs_n::guest_cr0::extension_type::enable(cr0);
    ::vmcs_n::guest_cr0::numeric_error::enable(cr0);
    ::vmcs_n::guest_cr0::not_write_through::enable(cr0);
    ::vmcs_n::guest_cr0::cache_disable::enable(cr0);
    ::vmcs_n::guest_cr0::set(cr0);

    ::vmcs_n::value_type cr4 = 0;
    ::vmcs_n::guest_cr4::vmx_enable_bit::enable(cr4);
    ::vmcs_n::guest_cr4::set(cr4);

    ::vmcs_n::guest_cr3::set(0);
    ::intel_x64::cr2::set(0);

    ::vmcs_n::value_type ds_ar = 0;
    ::vmcs_n::guest_ds_access_rights::type::set(ds_ar, 0x3);
    ::vmcs_n::guest_ds_access_rights::s::enable(ds_ar);
    ::vmcs_n::guest_ds_access_rights::present::enable(ds_ar);
    ::vmcs_n::guest_ds_selector::set(0);
    ::vmcs_n::guest_ds_base::set(0);
    ::vmcs_n::guest_ds_limit::set(0xFFFF);
    ::vmcs_n::guest_ds_access_rights::set(ds_ar);

    ::vmcs_n::value_type es_ar = 0;
    ::vmcs_n::guest_es_access_rights::type::set(es_ar, 0x3);
    ::vmcs_n::guest_es_access_rights::s::enable(es_ar);
    ::vmcs_n::guest_es_access_rights::present::enable(es_ar);
    ::vmcs_n::guest_es_selector::set(0);
    ::vmcs_n::guest_es_base::set(0);
    ::vmcs_n::guest_es_limit::set(0xFFFF);
    ::vmcs_n::guest_es_access_rights::set(es_ar);

    ::vmcs_n::value_type fs_ar = 0;
    ::vmcs_n::guest_fs_access_rights::type::set(fs_ar, 0x3);
    ::vmcs_n::guest_fs_access_rights::s::enable(fs_ar);
    ::vmcs_n::guest_fs_access_rights::present::enable(fs_ar);
    ::vmcs_n::guest_fs_selector::set(0);
    ::vmcs_n::guest_fs_base::set(0);
    ::vmcs_n::guest_fs_limit::set(0xFFFF);
    ::vmcs_n::guest_fs_access_rights::set(fs_ar);

    ::vmcs_n::value_type gs_ar = 0;
    ::vmcs_n::guest_gs_access_rights::type::set(gs_ar, 0x3);
    ::vmcs_n::guest_gs_access_rights::s::enable(gs_ar);
    ::vmcs_n::guest_gs_access_rights::present::enable(gs_ar);
    ::vmcs_n::guest_gs_selector::set(0);
    ::vmcs_n::guest_gs_base::set(0);
    ::vmcs_n::guest_gs_limit::set(0xFFFF);
    ::vmcs_n::guest_gs_access_rights::set(gs_ar);

    ::vmcs_n::value_type ss_ar = 0;
    ::vmcs_n::guest_ss_access_rights::type::set(ss_ar, 0x3);
    ::vmcs_n::guest_ss_access_rights::s::enable(ss_ar);
    ::vmcs_n::guest_ss_access_rights::present::enable(ss_ar);
    ::vmcs_n::guest_ss_selector::set(0);
    ::vmcs_n::guest_ss_base::set(0);
    ::vmcs_n::guest_ss_limit::set(0xFFFF);
    ::vmcs_n::guest_ss_access_rights::set(ss_ar);

    ::vmcs_n::value_type cs_ar = 0;
    ::vmcs_n::guest_cs_access_rights::type::set(cs_ar, 0xB);
    ::vmcs_n::guest_cs_access_rights::s::enable(cs_ar);
    ::vmcs_n::guest_cs_access_rights::present::enable(cs_ar);
    auto vector_segment = ::vmcs_n::exit_qualification::sipi::vector::get() << 8;
    ::vmcs_n::guest_cs_selector::set(vector_segment);
    ::vmcs_n::guest_cs_base::set(vector_segment << 4);
    ::vmcs_n::guest_cs_limit::set(0xFFFF);
    ::vmcs_n::guest_cs_access_rights::set(cs_ar);

    ::vmcs_n::value_type tr_ar = 0;
    ::vmcs_n::guest_tr_access_rights::type::set(tr_ar, 0xB);
    ::vmcs_n::guest_tr_access_rights::present::enable(tr_ar);
    ::vmcs_n::guest_tr_selector::set(0);
    ::vmcs_n::guest_tr_base::set(0);
    ::vmcs_n::guest_tr_limit::set(0xFFFF);
    ::vmcs_n::guest_tr_access_rights::set(tr_ar);

    ::vmcs_n::value_type ldtr_ar = 0;
    ::vmcs_n::guest_ldtr_access_rights::type::set(ldtr_ar, 0x2);
    ::vmcs_n::guest_ldtr_access_rights::present::enable(ldtr_ar);
    ::vmcs_n::guest_ldtr_selector::set(0);
    ::vmcs_n::guest_ldtr_base::set(0);
    ::vmcs_n::guest_ldtr_limit::set(0xFFFF);
    ::vmcs_n::guest_ldtr_access_rights::set(ldtr_ar);

    ::vmcs_n::guest_gdtr_base::set(0);
    ::vmcs_n::guest_gdtr_limit::set(0xFFFF);

    ::vmcs_n::guest_idtr_base::set(0);
    ::vmcs_n::guest_idtr_limit::set(0xFFFF);

    vmcs->save_state()->rax = 0;
    vmcs->save_state()->rbx = 0;
    vmcs->save_state()->rcx = 0;
    vmcs->save_state()->rdx = 0xF00;
    vmcs->save_state()->rdi = 0;
    vmcs->save_state()->rsi = 0;
    vmcs->save_state()->rbp = 0;
    vmcs->save_state()->rsp = 0;
    vmcs->save_state()->rip = 0;

    ::vmcs_n::guest_rflags::set(0x2);
    ::vmcs_n::guest_ia32_efer::set(0);

    ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::active);

    return true;
}

void vcpu::add_efi_handlers()
{
    hve()->enable_wrcr0_exiting(
        0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr0::get()
    );

    hve()->add_wrcr0_handler(
        control_register::handler_delegate_t::create<vcpu, &vcpu::efi_handle_wrcr0>(this)
    );

    hve()->enable_wrcr4_exiting(
        ::intel_x64::cr4::vmx_enable_bit::mask, ::intel_x64::vmcs::guest_cr4::get()
    );

    hve()->add_wrcr4_handler(
        control_register::handler_delegate_t::create<vcpu, &vcpu::efi_handle_wrcr4>(this)
    );

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_cpuid>(this)
    );

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_rdmsr>(this)
    );

    hve()->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_efer::addr,
        wrmsr::handler_delegate_t::create<vcpu, &vcpu::efi_handle_wrmsr_efer>(this)
    );

    hve()->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_perf_global_ctrl::addr,
        wrmsr::handler_delegate_t::create<vcpu, &vcpu::efi_handle_wrmsr_perf_global_ctrl>(this)
    );

    hve()->add_init_signal_handler(
        init_signal::handler_delegate_t::create<vcpu, &vcpu::efi_handle_init_signal>(this)
    );

    hve()->add_sipi_handler(
        sipi::handler_delegate_t::create<vcpu, &vcpu::efi_handle_sipi>(this)
    );
}

vcpu::vcpu(vcpuid::type id) :
    bfvmm::intel_x64::vcpu{id},
    m_hve{std::make_unique<eapis::intel_x64::hve>(exit_handler(), vmcs())}
{
    //    if (m_vic == nullptr) {
    //        m_vic = std::make_unique<eapis::intel_x64::vic>(m_hve.get());
    //    }
}

gsl::not_null<eapis::intel_x64::hve *> vcpu::hve()
{ return m_hve.get(); }

gsl::not_null<eapis::intel_x64::vic *> vcpu::vic()
{ return m_vic.get(); }

gsl::not_null<eapis::intel_x64::ept::memory_map *> vcpu::emm()
{ return m_emm.get(); }

}
}
