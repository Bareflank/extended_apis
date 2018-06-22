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
#include <vcpu/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/ept/helpers.h>
#include <hve/arch/intel_x64/ept/intrinsics.h>

namespace eapis
{
namespace intel_x64
{

// -----------------------------------------------------------------------------
// EFI Handlers
// -----------------------------------------------------------------------------

bool
vcpu::efi_handle_cpuid(gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax == 0xBF01 || vmcs->save_state()->rax == 0xBF00) {
        // bfvmm handles
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
        setter = set_bit(ret.rdx, ::intel_x64::cpuid::feature_information::edx::mtrr::from);
        vmcs->save_state()->rdx = setter;
    }
    else if ((leaf & 0xC0000000) == 0xC0000000) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
        vmcs->save_state()->rdx = 0;
    }
    else if (leaf == 0x0000000A) {
        vmcs->save_state()->rax = 0;
        vmcs->save_state()->rcx = 0;
    }
    else {
        vmcs->save_state()->rcx = ret.rcx;
    }

    return advance(vmcs);
}

bool
vcpu::efi_handle_rdmsr(gsl::not_null<vmcs_t *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);

    switch (msr) {
        case 0x613:
        case 0x619:
            vmcs->save_state()->rax = 0;
            vmcs->save_state()->rdx = 0;
            return advance(vmcs);
    }

    return false;
}

bool
vcpu::efi_handle_wrmsr(gsl::not_null<vmcs_t *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx);
    uint64_t val = ((vmcs->save_state()->rdx) << 0x20) | ((vmcs->save_state()->rax) & 0xFFFFFFFF);


    if (msr == ::intel_x64::msrs::ia32_efer::addr) {
        if (::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_disabled()) {
            return false;
        }

        if (get_bit<uint64_t>(val, ::intel_x64::msrs::ia32_efer::lme::from)) {
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
            ::vmcs_n::primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
            val |= ::intel_x64::msrs::ia32_efer::lma::mask;
        }

        ::vmcs_n::guest_ia32_efer::set(val);
        return advance(vmcs);
    }

    if (msr == ::intel_x64::msrs::ia32_perf_global_ctrl::addr) {
        val &= ~::vmcs_n::guest_ia32_perf_global_ctrl::reserved::mask;
        ::vmcs_n::guest_ia32_perf_global_ctrl::set(val);
        return advance(vmcs);
    }


    return false;
}

bool
vcpu::efi_handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    // only need access type 0 but eapis doesn't handle
    // these other access types properly when cr0 is emulated
    auto access_type = ::vmcs_n::exit_qualification::control_register_access::access_type::get();
    if (access_type == 2) {
        ::vmcs_n::guest_cr0::task_switched::disable(info.shadow);
        ::vmcs_n::guest_cr0::task_switched::disable(info.val);
    }
    else if (access_type == 3) {
        auto cur = set_bits(::vmcs_n::guest_cr0::get(), ::vmcs_n::exit_qualification::control_register_access::source_data::get(), ~0xFFFFULL);
        info.val = set_bits(cur, ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get(), ~0ULL);
        info.shadow = set_bits(info.shadow, ::vmcs_n::exit_qualification::control_register_access::source_data::get(), ~0xFFFFULL);
    }
    else if (access_type == 0) {
        info.shadow = info.val;
        ::vmcs_n::guest_cr0::extension_type::enable(info.val);
        ::vmcs_n::guest_cr0::numeric_error::enable(info.val);

        if (vmcs_n::guest_cr0::paging::is_disabled(info.val)) {
            ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
            ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();
            ::vmcs_n::guest_ia32_efer::lma::disable();
            ::vmcs_n::guest_ia32_efer::lme::disable();
        } else {
            ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
            ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
            ::vmcs_n::guest_ia32_efer::lma::enable();
            ::vmcs_n::guest_ia32_efer::lme::enable();
        }

    }
    else {
        throw std::runtime_error("efi_handle_wrcr0 invalid access_type " + std::to_string(access_type));
    }

    return true;
}

bool
vcpu::efi_handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    info.shadow = info.val;
    info.val = set_bits<::vmcs_n::value_type>(info.val, ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get(), ~0ULL);
    return true;
}

bool
vcpu::efi_handle_vmcall(gsl::not_null<vmcs_t *> vmcs)
{
    uint64_t core = thread_context_cpuid();
    uint64_t bf = 0xFB00;
    vmcs->save_state()->rax = static_cast<uint64_t>(bf | core);
    return advance(vmcs);
}

bool
vcpu::efi_handle_init_signal(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    m_vic->reset_from_init();
    ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::wait_for_sipi);
    bfalert_info(0, "init");
    return true;
}

bool
vcpu::efi_handle_sipi(gsl::not_null<vmcs_t *> vmcs)
{

    bfignored(vmcs);

    ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();

    ::vmcs_n::value_type s_cr0 = 0;
    ::vmcs_n::value_type s_cr4 = 0;
    ::vmcs_n::guest_cr0::extension_type::enable(s_cr0);
    ::vmcs_n::guest_cr0::numeric_error::enable(s_cr0);
    ::vmcs_n::guest_cr0::not_write_through::enable(s_cr0);
    ::vmcs_n::guest_cr0::cache_disable::enable(s_cr0);
    ::vmcs_n::guest_cr4::vmx_enable_bit::enable(s_cr4);
    ::vmcs_n::guest_cr0::set(s_cr0);
    ::vmcs_n::guest_cr4::set(s_cr4);
    ::vmcs_n::guest_cr3::set(0);

    ::intel_x64::cr2::set(0);

    ::vmcs_n::value_type s_ds_ar = 0;
    ::vmcs_n::guest_ds_access_rights::type::set(s_ds_ar, 0x3);
    ::vmcs_n::guest_ds_access_rights::s::enable(s_ds_ar);
    ::vmcs_n::guest_ds_access_rights::present::enable(s_ds_ar);
    ::vmcs_n::guest_ds_selector::set(0);
    ::vmcs_n::guest_ds_base::set(0);
    ::vmcs_n::guest_ds_limit::set(0xFFFF);
    ::vmcs_n::guest_ds_access_rights::set(s_ds_ar);

    ::vmcs_n::value_type s_es_ar = 0;
    ::vmcs_n::guest_es_access_rights::type::set(s_es_ar, 0x3);
    ::vmcs_n::guest_es_access_rights::s::enable(s_es_ar);
    ::vmcs_n::guest_es_access_rights::present::enable(s_es_ar);
    ::vmcs_n::guest_es_selector::set(0);
    ::vmcs_n::guest_es_base::set(0);
    ::vmcs_n::guest_es_limit::set(0xFFFF);
    ::vmcs_n::guest_es_access_rights::set(s_es_ar);

    ::vmcs_n::value_type s_fs_ar = 0;
    ::vmcs_n::guest_fs_access_rights::type::set(s_fs_ar, 0x3);
    ::vmcs_n::guest_fs_access_rights::s::enable(s_fs_ar);
    ::vmcs_n::guest_fs_access_rights::present::enable(s_fs_ar);
    ::vmcs_n::guest_fs_selector::set(0);
    ::vmcs_n::guest_fs_base::set(0);
    ::vmcs_n::guest_fs_limit::set(0xFFFF);
    ::vmcs_n::guest_fs_access_rights::set(s_fs_ar);

    ::vmcs_n::value_type s_gs_ar = 0;
    ::vmcs_n::guest_gs_access_rights::type::set(s_gs_ar, 0x3);
    ::vmcs_n::guest_gs_access_rights::s::enable(s_gs_ar);
    ::vmcs_n::guest_gs_access_rights::present::enable(s_gs_ar);
    ::vmcs_n::guest_gs_selector::set(0);
    ::vmcs_n::guest_gs_base::set(0);
    ::vmcs_n::guest_gs_limit::set(0xFFFF);
    ::vmcs_n::guest_gs_access_rights::set(s_gs_ar);

    ::vmcs_n::value_type s_ss_ar = 0;
    ::vmcs_n::guest_ss_access_rights::type::set(s_ss_ar, 0x3);
    ::vmcs_n::guest_ss_access_rights::s::enable(s_ss_ar);
    ::vmcs_n::guest_ss_access_rights::present::enable(s_ss_ar);
    ::vmcs_n::guest_ss_selector::set(0);
    ::vmcs_n::guest_ss_base::set(0);
    ::vmcs_n::guest_ss_limit::set(0xFFFF);
    ::vmcs_n::guest_ss_access_rights::set(s_ss_ar);

    ::vmcs_n::value_type s_cs_ar = 0;
    ::vmcs_n::guest_cs_access_rights::type::set(s_cs_ar, 0xB);
    ::vmcs_n::guest_cs_access_rights::s::enable(s_cs_ar);
    ::vmcs_n::guest_cs_access_rights::present::enable(s_cs_ar);
    auto vector_segment = ::vmcs_n::exit_qualification::sipi::vector::get() << 8;
    ::vmcs_n::guest_cs_selector::set(vector_segment);
    ::vmcs_n::guest_cs_base::set(vector_segment << 4);
    ::vmcs_n::guest_cs_limit::set(0xFFFF);
    ::vmcs_n::guest_cs_access_rights::set(s_cs_ar);

    ::vmcs_n::value_type s_tr_ar = 0;
    ::vmcs_n::guest_tr_access_rights::type::set(s_tr_ar, 0xB);
    ::vmcs_n::guest_tr_access_rights::present::enable(s_tr_ar);
    ::vmcs_n::guest_tr_selector::set(0);
    ::vmcs_n::guest_tr_base::set(0);
    ::vmcs_n::guest_tr_limit::set(0xFFFF);
    ::vmcs_n::guest_tr_access_rights::set(s_tr_ar);

    ::vmcs_n::value_type s_ldtr_ar = 0;
    ::vmcs_n::guest_ldtr_access_rights::type::set(s_ldtr_ar, 0x2);
    ::vmcs_n::guest_ldtr_access_rights::present::enable(s_ldtr_ar);
    ::vmcs_n::guest_ldtr_selector::set(0);
    ::vmcs_n::guest_ldtr_base::set(0);
    ::vmcs_n::guest_ldtr_limit::set(0xFFFF);
    ::vmcs_n::guest_ldtr_access_rights::set(s_ldtr_ar);

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
    bfalert_info(0, "sipi");

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

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_wrmsr>(this)
        );

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::init_signal,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_init_signal>(this)
        );

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::sipi,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_sipi>(this)
        );

    exit_handler()->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
        ::handler_delegate_t::create<vcpu, &vcpu::efi_handle_vmcall>(this)
        );
}

vcpu::vcpu(vcpuid::type id) :
    bfvmm::intel_x64::vcpu{id},
    m_emm{std::make_unique<eapis::intel_x64::ept::memory_map>()},
    m_hve{std::make_unique<eapis::intel_x64::hve>(exit_handler(), vmcs())},
    m_vic{std::make_unique<eapis::intel_x64::vic>(m_hve.get(), m_emm.get())}
{
    if (get_platform_info()->efi.enabled) {
        bfdebug_info(0, "Enabling EFI exit handlers");
        this->add_efi_handlers();
    }
}

gsl::not_null<eapis::intel_x64::hve *> vcpu::hve()
{
    return m_hve.get();
}

gsl::not_null<eapis::intel_x64::vic *> vcpu::vic()
{
    return m_vic.get();
}

gsl::not_null<eapis::intel_x64::ept::memory_map *> vcpu::emm()
{
    return m_emm.get();
}

}
}
