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

#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

apis::apis(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
) :
    m_vmcs{vmcs},
    m_exit_handler{exit_handler}
{ }

//==========================================================================
// MISC
//==========================================================================

//--------------------------------------------------------------------------
// EPT
//--------------------------------------------------------------------------

gsl::not_null<ept_handler *>
apis::ept()
{ return m_ept_handler.get(); }

void
apis::set_eptp(ept::mmap &map)
{
    if (!m_ept_handler) {
        m_ept_handler = std::make_unique<ept_handler>();
    }

    m_ept_handler->set_eptp(&map);
}

void
apis::disable_ept()
{
    if (m_ept_handler) {
        m_ept_handler->set_eptp(nullptr);
    }
}

//--------------------------------------------------------------------------
// VPID
//--------------------------------------------------------------------------

gsl::not_null<vpid_handler *>
apis::vpid()
{ return m_vpid_handler.get(); }

void
apis::enable_vpid()
{
    if (!m_vpid_handler) {
        m_vpid_handler = std::make_unique<vpid_handler>();
    }

    m_vpid_handler->enable();
}

void
apis::disable_vpid()
{
    if (m_vpid_handler) {
        m_vpid_handler->disable();
    }
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// Control Register
//--------------------------------------------------------------------------

gsl::not_null<control_register_handler *>
apis::control_register()
{ return m_control_register_handler.get(); }

void
apis::enable_wrcr0_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register_handler->enable_wrcr0_exiting(mask, shadow);
}

void
apis::enable_wrcr4_exiting(
    vmcs_n::value_type mask, vmcs_n::value_type shadow)
{
    check_crall();
    m_control_register_handler->enable_wrcr4_exiting(mask, shadow);
}

void
apis::add_wrcr0_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_crall();
    m_control_register_handler->add_wrcr0_handler(d);
}

void
apis::add_rdcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_rdcr3();
    m_control_register_handler->add_rdcr3_handler(d);
}

void
apis::add_wrcr3_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_wrcr3();
    m_control_register_handler->add_wrcr3_handler(d);
}

void
apis::add_wrcr4_handler(
    const control_register_handler::handler_delegate_t &d)
{
    check_crall();
    m_control_register_handler->add_wrcr4_handler(d);
}

//--------------------------------------------------------------------------
// CPUID
//--------------------------------------------------------------------------

gsl::not_null<cpuid_handler *>
apis::cpuid()
{ return m_cpuid_handler.get(); }

void
apis::add_cpuid_handler(
    cpuid_handler::leaf_t leaf, const cpuid_handler::handler_delegate_t &d)
{
    if (!m_cpuid_handler) {
        m_cpuid_handler = std::make_unique<cpuid_handler>(this);
    }

    m_cpuid_handler->add_handler(leaf, d);
}

//--------------------------------------------------------------------------
// EPT Misconfiguration
//--------------------------------------------------------------------------

gsl::not_null<ept_misconfiguration_handler *>
apis::ept_misconfiguration()
{ return m_ept_misconfiguration_handler.get(); }

void
apis::add_ept_misconfiguration_handler(
    const ept_misconfiguration_handler::handler_delegate_t &d)
{
    if (!m_ept_misconfiguration_handler) {
        m_ept_misconfiguration_handler = std::make_unique<ept_misconfiguration_handler>(this);
    }

    m_ept_misconfiguration_handler->add_handler(d);
}

//--------------------------------------------------------------------------
// EPT Violation
//--------------------------------------------------------------------------

gsl::not_null<ept_violation_handler *>
apis::ept_violation()
{ return m_ept_violation_handler.get(); }

void
apis::add_ept_read_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_read_handler(d);
}

void
apis::add_ept_write_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_write_handler(d);
}

void
apis::add_ept_execute_violation_handler(
    const ept_violation_handler::handler_delegate_t &d)
{
    if (!m_ept_violation_handler) {
        m_ept_violation_handler = std::make_unique<ept_violation_handler>(this);
    }

    m_ept_violation_handler->add_execute_handler(d);
}

//--------------------------------------------------------------------------
// External Interrupt
//--------------------------------------------------------------------------

gsl::not_null<external_interrupt_handler *>
apis::external_interrupt()
{ return m_external_interrupt_handler.get(); }

void
apis::add_external_interrupt_handler(
    const external_interrupt_handler::handler_delegate_t &d)
{
    if (!m_external_interrupt_handler) {
        m_external_interrupt_handler = std::make_unique<external_interrupt_handler>(this);
        m_external_interrupt_handler->enable_exiting();
    }

    m_external_interrupt_handler->add_handler(d);
}

void
apis::disable_external_interrupts()
{
    if (m_external_interrupt_handler) {
        m_external_interrupt_handler->disable_exiting();
    }
}

//--------------------------------------------------------------------------
// INIT Signal
//--------------------------------------------------------------------------

gsl::not_null<init_signal_handler *>
apis::init_signal()
{ return m_init_signal_handler.get(); }

void
apis::add_init_signal_handler(
    const init_signal_handler::handler_delegate_t &d)
{
    if (!m_init_signal_handler) {
        m_init_signal_handler = std::make_unique<init_signal_handler>(this);
    }

    m_init_signal_handler->add_handler(d);
}

//--------------------------------------------------------------------------
// Interrupt Window
//--------------------------------------------------------------------------

gsl::not_null<interrupt_window_handler *>
apis::interrupt_window()
{ return m_interrupt_window_handler.get(); }

void
apis::trap_on_next_interrupt_window()
{
    if (!m_interrupt_window_handler) {
        m_interrupt_window_handler = std::make_unique<interrupt_window_handler>(this);
    }

    m_interrupt_window_handler->enable_exiting();
}

void
apis::disable_interrupt_window()
{
    if (!m_interrupt_window_handler) {
        m_interrupt_window_handler = std::make_unique<interrupt_window_handler>(this);
    }

    m_interrupt_window_handler->disable_exiting();
}

void
apis::add_interrupt_window_handler(
    const interrupt_window_handler::handler_delegate_t &d)
{
    if (!m_interrupt_window_handler) {
        m_interrupt_window_handler = std::make_unique<interrupt_window_handler>(this);
    }

    m_interrupt_window_handler->add_handler(d);
}

bool
apis::is_interrupt_window_open()
{
    if (GSL_UNLIKELY(!m_interrupt_window_handler)) {
        m_interrupt_window_handler = std::make_unique<interrupt_window_handler>(this);
    }

    return m_interrupt_window_handler->is_open();
}

void
apis::inject_external_interrupt(uint64_t vector)
{
    if (GSL_UNLIKELY(!m_interrupt_window_handler)) {
        m_interrupt_window_handler = std::make_unique<interrupt_window_handler>(this);
    }

    return m_interrupt_window_handler->inject(vector);
}

//--------------------------------------------------------------------------
// IO Instruction
//--------------------------------------------------------------------------

gsl::not_null<io_instruction_handler *>
apis::io_instruction()
{ return m_io_instruction_handler.get(); }

void
apis::add_io_instruction_handler(
    vmcs_n::value_type port,
    const io_instruction_handler::handler_delegate_t &in_d,
    const io_instruction_handler::handler_delegate_t &out_d)
{
    check_io_bitmaps();

    if (!m_io_instruction_handler) {
        m_io_instruction_handler = std::make_unique<io_instruction_handler>(this);
    }

    m_io_instruction_handler->add_handler(port, in_d, out_d);
}

//--------------------------------------------------------------------------
// Monitor Trap
//--------------------------------------------------------------------------

gsl::not_null<monitor_trap_handler *>
apis::monitor_trap()
{ return m_monitor_trap_handler.get(); }

void
apis::add_monitor_trap_handler(
    const monitor_trap_handler::handler_delegate_t &d)
{
    if (!m_monitor_trap_handler) {
        m_monitor_trap_handler = std::make_unique<monitor_trap_handler>(this);
    }

    m_monitor_trap_handler->add_handler(d);
}

void
apis::enable_monitor_trap_flag()
{
    if (!m_monitor_trap_handler) {
        m_monitor_trap_handler = std::make_unique<monitor_trap_handler>(this);
    }

    m_monitor_trap_handler->enable();
}

//--------------------------------------------------------------------------
// Move DR
//--------------------------------------------------------------------------

gsl::not_null<mov_dr_handler *>
apis::mov_dr()
{ return m_mov_dr_handler.get(); }

void
apis::add_mov_dr_handler(
    const mov_dr_handler::handler_delegate_t &d)
{
    if (!m_mov_dr_handler) {
        m_mov_dr_handler = std::make_unique<mov_dr_handler>(this);
    }

    m_mov_dr_handler->add_handler(d);
}

//--------------------------------------------------------------------------
// Read MSR
//--------------------------------------------------------------------------

gsl::not_null<rdmsr_handler *>
apis::rdmsr()
{ return m_rdmsr_handler.get(); }

void
apis::pass_through_all_rdmsr_handler_accesses()
{ check_rdmsr_handler(); }

void
apis::add_rdmsr_handler(
    vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d)
{
    check_rdmsr_handler();
    m_rdmsr_handler->add_handler(msr, d);
}

//--------------------------------------------------------------------------
// SIPI
//--------------------------------------------------------------------------

gsl::not_null<sipi_handler *>
apis::sipi()
{ return m_sipi_handler.get(); }

void
apis::add_sipi_handler(const sipi_handler::handler_delegate_t &d)
{
    if (!m_sipi_handler) {
        m_sipi_handler = std::make_unique<sipi_handler>(this);
    }

    m_sipi_handler->add_handler(d);
}

//--------------------------------------------------------------------------
// Write MSR
//--------------------------------------------------------------------------

gsl::not_null<wrmsr_handler *>
apis::wrmsr()
{ return m_wrmsr_handler.get(); }

void
apis::pass_through_all_wrmsr_handler_accesses()
{ check_wrmsr_handler(); }

void
apis::add_wrmsr_handler(
    vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d)
{
    check_wrmsr_handler();
    m_wrmsr_handler->add_handler(msr, d);
}

//==========================================================================
// Bitmaps
//==========================================================================

gsl::span<uint8_t>
apis::msr_bitmap()
{ return gsl::make_span(m_msr_bitmap.get(), ::x64::pt::page_size); }

gsl::span<uint8_t>
apis::io_bitmaps()
{ return gsl::make_span(m_io_bitmaps.get(), ::x64::pt::page_size * 2); }

//==========================================================================
// Resources
//==========================================================================

void
apis::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, d); }

//==========================================================================
// Private
//==========================================================================

void
apis::check_crall()
{
    if (!m_control_register_handler) {
        m_control_register_handler = std::make_unique<control_register_handler>(this);
    }
}

void
apis::check_rdcr3()
{
    check_crall();

    if (!m_is_rdcr3_enabled) {
        m_is_rdcr3_enabled = true;
        m_control_register_handler->enable_rdcr3_exiting();
    }
}

void
apis::check_wrcr3()
{
    check_crall();

    if (!m_is_wrcr3_enabled) {
        m_is_wrcr3_enabled = true;
        m_control_register_handler->enable_wrcr3_exiting();
    }
}

void
apis::check_io_bitmaps()
{
    using namespace vmcs_n;

    if (!m_io_bitmaps) {
        m_io_bitmaps = std::make_unique<uint8_t[]>(::x64::pt::page_size * 2);

        address_of_io_bitmap_a::set(g_mm->virtptr_to_physint(&m_io_bitmaps[0x0000]));
        address_of_io_bitmap_b::set(g_mm->virtptr_to_physint(&m_io_bitmaps[010000]));

        primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
    }
}

void
apis::check_msr_bitmap()
{
    using namespace vmcs_n;

    if (!m_msr_bitmap) {
        m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::pt::page_size);

        address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
        primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
    }
}

void
apis::check_rdmsr_handler()
{
    check_msr_bitmap();

    if (!m_rdmsr_handler) {
        m_rdmsr_handler = std::make_unique<rdmsr_handler>(this);
    }
}

void
apis::check_wrmsr_handler()
{
    check_msr_bitmap();

    if (!m_wrmsr_handler) {
        m_wrmsr_handler = std::make_unique<wrmsr_handler>(this);
    }
}

}
}


















// bool init_done = false;
// bool sipi_handler_done = false;

// void
// apis::enable_efi()
// {
//     // if (m_emm == nullptr) {
//     //     m_emm = std::make_unique<ept::memory_map>();
//     // }

//     // if (m_vic == nullptr) {
//     //     m_vic = std::make_unique<vic>(m_hve.get());
//     // }

//     // this->add_efi_handlers();

//     // ::vmcs_n::guest_ia32_perf_global_ctrl::reserved::set(0);
//     // ept::identity_map(*m_emm, 0, 0x900000000 - 0x1000);
//     // ept::enable_ept(ept::eptp(*m_emm));
//     // m_hve->enable_vpid();
// }

// // -----------------------------------------------------------------------------
// // EFI Handlers
// // -----------------------------------------------------------------------------

// /// This has to be registered through the base exit_handler because the EAPIs
// /// cpuid handlers are keyed off of {leaf, subleaf}, but in practice, when
// /// firmware calls cpuid, it may not clear out rcx, resulting in random
// /// subleaf values. Until the EAPIs can account for this scenario, this
// /// function will need bypass the EAPIs cpuid interface.

// bool
// apis::efi_handle_cpuid(gsl::not_null<vmcs_t *> vmcs)
// {
//     static constexpr uint32_t centaur_base = 0xC0000000;

//     if (vmcs->save_state()->rax == 0xBF01 || vmcs->save_state()->rax == 0xBF00) {
//         return false;
//     }

//     auto leaf = vmcs->save_state()->rax;
//     auto ret =
//         ::x64::cpuid_handler::get(
//             gsl::narrow_cast<::x64::cpuid_handler::field_type>(vmcs->save_state()->rax),
//             gsl::narrow_cast<::x64::cpuid_handler::field_type>(vmcs->save_state()->rbx),
//             gsl::narrow_cast<::x64::cpuid_handler::field_type>(vmcs->save_state()->rcx),
//             gsl::narrow_cast<::x64::cpuid_handler::field_type>(vmcs->save_state()->rdx)
//         );

//     vmcs->save_state()->rax = ret.rax;
//     vmcs->save_state()->rbx = ret.rbx;
//     vmcs->save_state()->rdx = ret.rdx;

//     if (leaf == ::intel_x64::cpuid_handler::feature_information::addr) {
//         uint64_t setter = ret.rcx;
//         setter = clear_bit(setter, ::intel_x64::cpuid_handler::feature_information::ecx::xsave::from);
//         setter = clear_bit(setter, ::intel_x64::cpuid_handler::feature_information::ecx::osxsave::from);
//         setter = clear_bit(setter, ::intel_x64::cpuid_handler::feature_information::ecx::vmx::from);
//         vmcs->save_state()->rcx = setter;

//         //TODO: handle MTRR writes
//         setter = clear_bit(ret.rdx, ::intel_x64::cpuid_handler::feature_information::edx::mtrr::from);
//         vmcs->save_state()->rdx = setter;
//     }
//     else if ((leaf & centaur_base) == centaur_base) {
//         bfalert_nhex(0, "centaur leaf", leaf);
//         bfalert_nhex(0, "centaur subleaf", vmcs->save_state()->rcx);
//         vmcs->save_state()->rax = 0;
//         vmcs->save_state()->rcx = 0;
//         vmcs->save_state()->rdx = 0;
//     }
//     else if (leaf == ::intel_x64::cpuid_handler::arch_perf_monitoring::addr) {
//         vmcs->save_state()->rax = 0;
//         vmcs->save_state()->rcx = 0;
//     }
//     else {
//         vmcs->save_state()->rcx = ret.rcx;
//     }

//     return advance(vmcs);
// }

// /// This handler has to bypass the EAPIs' rdmsr_handler interface because once
// /// you register to handle an msr with the rdmsr_handler class, it reads at the
// /// given address. But an MSR may or may not be implemented on a
// /// given system and if it's not, a GP will be raised.
// ///
// /// It may be reasonable to add these two addresses to the QUIRK'd out ones in
// /// emulate_rdmsr_handler since they aren't architectural.
// ///
// bool
// apis::efi_handle_rdmsr_handler(gsl::not_null<vmcs_t *> vmcs)
// {
//     static constexpr uint32_t pkg_perf_status = 0x613;
//     static constexpr uint32_t dram_energy_status = 0x619;

//     const auto msr = vmcs->save_state()->rcx;

//     if (msr == pkg_perf_status || msr == dram_energy_status) {
//         vmcs->save_state()->rax = 0;
//         vmcs->save_state()->rdx = 0;
//         return advance(vmcs);
//     }

//     return false;
// }

// bool
// apis::efi_handle_wrmsr_handler_efer(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
// {
//     bfignored(vmcs);

//     if (::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::is_disabled()) {
//         return true;
//     }

//     if (get_bit(info.val, ::intel_x64::msrs::ia32_efer::lme::from) != 0U) {
//         uint64_t s_cr0 = 0;
//         ::vmcs_n::guest_cr0::protection_enable::enable(s_cr0);
//         ::vmcs_n::guest_cr0::extension_type::enable(s_cr0);
//         ::vmcs_n::guest_cr0::numeric_error::enable(s_cr0);
//         ::vmcs_n::guest_cr0::write_protect::enable(s_cr0);
//         ::vmcs_n::guest_cr0::not_write_through::enable(s_cr0);
//         ::vmcs_n::guest_cr0::cache_disable::enable(s_cr0);
//         ::vmcs_n::guest_cr0::paging::enable(s_cr0);
//         ::vmcs_n::guest_cr0::set(s_cr0);

//         ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
//         ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
//         info.val |= ::intel_x64::msrs::ia32_efer::lma::mask;
//     }

//     return true;
// }

// bool
// apis::efi_handle_wrmsr_handler_perf_global_ctrl(gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
// {
//     bfignored(vmcs);
//     ::vmcs_n::guest_ia32_perf_global_ctrl::reserved::set(info.val, 0);
//     return true;
// }

// bool
// apis::efi_handle_wrcr0(gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
// {
//     bfignored(vmcs);
//     using namespace ::vmcs_n::exit_qualification::control_register_access;

//     // only need access type 0 but eapis doesn't handle
//     // these other access types properly when cr0 is emulated
//     auto access_type = access_type::get();
//     switch (access_type) {
//         case access_type::mov_to_cr:
//             info.shadow = info.val;
//             ::vmcs_n::guest_cr0::extension_type::enable(info.val);
//             ::vmcs_n::guest_cr0::numeric_error::enable(info.val);

//             if (vmcs_n::guest_cr0::paging::is_disabled(info.val)) {
//                 ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
//                 ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();
//                 ::vmcs_n::guest_ia32_efer::lma::disable();
//                 ::vmcs_n::guest_ia32_efer::lme::disable();
//             }
//             else {
//                 ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
//                 ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::enable();
//                 ::vmcs_n::guest_ia32_efer::lma::enable();
//                 ::vmcs_n::guest_ia32_efer::lme::enable();
//             }
//             return true;

//         case access_type::clts:
//             ::vmcs_n::guest_cr0::task_switched::disable(info.shadow);
//             ::vmcs_n::guest_cr0::task_switched::disable(info.val);
//             return true;

//         case access_type::lmsw: {
//             auto cur = set_bits(::vmcs_n::guest_cr0::get(), source_data::get(), ~0xFFFFULL);
//             info.val = set_bits(cur, ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get(), ~0ULL);
//             info.shadow = set_bits(info.shadow, source_data::get(), ~0xFFFFULL);
//             return true;
//         }

//         case access_type::mov_from_cr:
//         default:
//             throw std::runtime_error("efi_handle_wrcr0 invalid access_type " + std::to_string(access_type));
//     }
// }

// bool
// apis::efi_handle_wrcr4(gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
// {
//     bfignored(vmcs);
//     info.shadow = info.val;
//     info.val = set_bits(
//                    info.val, ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get(), ~0ULL
//                );
//     return true;
// }

// bool
// apis::efi_handle_init_signal_handler(gsl::not_null<vmcs_t *> vmcs)
// {
//     bfignored(vmcs);
//     ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::wait_for_sipi_handler);
//     init_done = true;
//     return true;
// }

// bool
// apis::efi_handle_sipi_handler(gsl::not_null<vmcs_t *> vmcs)
// {
//     bfignored(vmcs);

//     if (!sipi_handler_done) {
//         sipi_handler_done = true;
//         return true;
//     }

//     ::vmcs_n::secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
//     ::vmcs_n::vm_entry_controls::ia_32e_mode_guest::disable();

//     ::vmcs_n::value_type cr0 = 0;
//     ::vmcs_n::guest_cr0::extension_type::enable(cr0);
//     ::vmcs_n::guest_cr0::numeric_error::enable(cr0);
//     ::vmcs_n::guest_cr0::not_write_through::enable(cr0);
//     ::vmcs_n::guest_cr0::cache_disable::enable(cr0);
//     ::vmcs_n::guest_cr0::set(cr0);

//     ::vmcs_n::value_type cr4 = 0;
//     ::vmcs_n::guest_cr4::vmx_enable_bit::enable(cr4);
//     ::vmcs_n::guest_cr4::set(cr4);

//     ::vmcs_n::guest_cr3::set(0);
//     ::intel_x64::cr2::set(0);

//     ::vmcs_n::value_type ds_ar = 0;
//     ::vmcs_n::guest_ds_access_rights::type::set(ds_ar, 0x3);
//     ::vmcs_n::guest_ds_access_rights::s::enable(ds_ar);
//     ::vmcs_n::guest_ds_access_rights::present::enable(ds_ar);
//     ::vmcs_n::guest_ds_selector::set(0);
//     ::vmcs_n::guest_ds_base::set(0);
//     ::vmcs_n::guest_ds_limit::set(0xFFFF);
//     ::vmcs_n::guest_ds_access_rights::set(ds_ar);

//     ::vmcs_n::value_type es_ar = 0;
//     ::vmcs_n::guest_es_access_rights::type::set(es_ar, 0x3);
//     ::vmcs_n::guest_es_access_rights::s::enable(es_ar);
//     ::vmcs_n::guest_es_access_rights::present::enable(es_ar);
//     ::vmcs_n::guest_es_selector::set(0);
//     ::vmcs_n::guest_es_base::set(0);
//     ::vmcs_n::guest_es_limit::set(0xFFFF);
//     ::vmcs_n::guest_es_access_rights::set(es_ar);

//     ::vmcs_n::value_type fs_ar = 0;
//     ::vmcs_n::guest_fs_access_rights::type::set(fs_ar, 0x3);
//     ::vmcs_n::guest_fs_access_rights::s::enable(fs_ar);
//     ::vmcs_n::guest_fs_access_rights::present::enable(fs_ar);
//     ::vmcs_n::guest_fs_selector::set(0);
//     ::vmcs_n::guest_fs_base::set(0);
//     ::vmcs_n::guest_fs_limit::set(0xFFFF);
//     ::vmcs_n::guest_fs_access_rights::set(fs_ar);

//     ::vmcs_n::value_type gs_ar = 0;
//     ::vmcs_n::guest_gs_access_rights::type::set(gs_ar, 0x3);
//     ::vmcs_n::guest_gs_access_rights::s::enable(gs_ar);
//     ::vmcs_n::guest_gs_access_rights::present::enable(gs_ar);
//     ::vmcs_n::guest_gs_selector::set(0);
//     ::vmcs_n::guest_gs_base::set(0);
//     ::vmcs_n::guest_gs_limit::set(0xFFFF);
//     ::vmcs_n::guest_gs_access_rights::set(gs_ar);

//     ::vmcs_n::value_type ss_ar = 0;
//     ::vmcs_n::guest_ss_access_rights::type::set(ss_ar, 0x3);
//     ::vmcs_n::guest_ss_access_rights::s::enable(ss_ar);
//     ::vmcs_n::guest_ss_access_rights::present::enable(ss_ar);
//     ::vmcs_n::guest_ss_selector::set(0);
//     ::vmcs_n::guest_ss_base::set(0);
//     ::vmcs_n::guest_ss_limit::set(0xFFFF);
//     ::vmcs_n::guest_ss_access_rights::set(ss_ar);

//     ::vmcs_n::value_type cs_ar = 0;
//     ::vmcs_n::guest_cs_access_rights::type::set(cs_ar, 0xB);
//     ::vmcs_n::guest_cs_access_rights::s::enable(cs_ar);
//     ::vmcs_n::guest_cs_access_rights::present::enable(cs_ar);
//     auto vector_segment = ::vmcs_n::exit_qualification::sipi_handler::vector::get() << 8;
//     ::vmcs_n::guest_cs_selector::set(vector_segment);
//     ::vmcs_n::guest_cs_base::set(vector_segment << 4);
//     ::vmcs_n::guest_cs_limit::set(0xFFFF);
//     ::vmcs_n::guest_cs_access_rights::set(cs_ar);

//     ::vmcs_n::value_type tr_ar = 0;
//     ::vmcs_n::guest_tr_access_rights::type::set(tr_ar, 0xB);
//     ::vmcs_n::guest_tr_access_rights::present::enable(tr_ar);
//     ::vmcs_n::guest_tr_selector::set(0);
//     ::vmcs_n::guest_tr_base::set(0);
//     ::vmcs_n::guest_tr_limit::set(0xFFFF);
//     ::vmcs_n::guest_tr_access_rights::set(tr_ar);

//     ::vmcs_n::value_type ldtr_ar = 0;
//     ::vmcs_n::guest_ldtr_access_rights::type::set(ldtr_ar, 0x2);
//     ::vmcs_n::guest_ldtr_access_rights::present::enable(ldtr_ar);
//     ::vmcs_n::guest_ldtr_selector::set(0);
//     ::vmcs_n::guest_ldtr_base::set(0);
//     ::vmcs_n::guest_ldtr_limit::set(0xFFFF);
//     ::vmcs_n::guest_ldtr_access_rights::set(ldtr_ar);

//     ::vmcs_n::guest_gdtr_base::set(0);
//     ::vmcs_n::guest_gdtr_limit::set(0xFFFF);

//     ::vmcs_n::guest_idtr_base::set(0);
//     ::vmcs_n::guest_idtr_limit::set(0xFFFF);

//     vmcs->save_state()->rax = 0;
//     vmcs->save_state()->rbx = 0;
//     vmcs->save_state()->rcx = 0;
//     vmcs->save_state()->rdx = 0xF00;
//     vmcs->save_state()->rdi = 0;
//     vmcs->save_state()->rsi = 0;
//     vmcs->save_state()->rbp = 0;
//     vmcs->save_state()->rsp = 0;
//     vmcs->save_state()->rip = 0;

//     ::vmcs_n::guest_rflags::set(0x2);
//     ::vmcs_n::guest_ia32_efer::set(0);

//     ::vmcs_n::guest_activity_state::set(::vmcs_n::guest_activity_state::active);

//     return true;
// }

// void apis::add_efi_handlers()
// {
//     hve()->enable_wrcr0_exiting(
//         0xFFFFFFFFFFFFFFFF, ::intel_x64::vmcs::guest_cr0::get()
//     );

//     hve()->add_wrcr0_handler(
//         control_register_handler::handler_delegate_t::create<apis, &apis::efi_handle_wrcr0>(this)
//     );

//     hve()->enable_wrcr4_exiting(
//         ::intel_x64::cr4::vmx_enable_bit::mask, ::intel_x64::vmcs::guest_cr4::get()
//     );

//     hve()->add_wrcr4_handler(
//         control_register_handler::handler_delegate_t::create<apis, &apis::efi_handle_wrcr4>(this)
//     );

//     exit_handler()->add_handler(
//         ::intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid,
//         ::handler_delegate_t::create<apis, &apis::efi_handle_cpuid>(this)
//     );

//     exit_handler()->add_handler(
//         ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr_handler,
//         ::handler_delegate_t::create<apis, &apis::efi_handle_rdmsr_handler>(this)
//     );

//     hve()->add_wrmsr_handler(
//         ::intel_x64::msrs::ia32_efer::addr,
//         wrmsr_handler::handler_delegate_t::create<apis, &apis::efi_handle_wrmsr_handler_efer>(this)
//     );

//     hve()->add_wrmsr_handler(
//         ::intel_x64::msrs::ia32_perf_global_ctrl::addr,
//         wrmsr_handler::handler_delegate_t::create<apis, &apis::efi_handle_wrmsr_handler_perf_global_ctrl>(this)
//     );

//     hve()->add_init_signal_handler(
//         init_signal_handler::handler_delegate_t::create<apis, &apis::efi_handle_init_signal_handler>(this)
//     );

//     hve()->add_sipi_handler(
//         sipi_handler::handler_delegate_t::create<apis, &apis::efi_handle_sipi_handler>(this)
//     );
// }
