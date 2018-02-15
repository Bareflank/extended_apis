//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn           <quinnr@ainfosec.com>
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

#include <bfgsl.h>
#include <bfdebug.h>

#include <intrinsics.h>
#include "../../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"

// Don't use "" includes in cpp files. Search for them instead.














namespace proc_ctls = ::intel_x64::vmcs::primary_processor_based_vm_execution_controls;
namespace entry_irq_info = ::intel_x64::vmcs::vm_entry_interruption_information;
namespace entry_irq_type = ::intel_x64::vmcs::vm_entry_interruption_information::interruption_type;
namespace exit_irq_info = ::intel_x64::vmcs::vm_exit_interruption_information;
namespace exit_irq_type = ::intel_x64::vmcs::vm_exit_interruption_information::interruption_type;
namespace guest_irq_state = ::intel_x64::vmcs::guest_interruptibility_state;
namespace guest_act_state = ::intel_x64::vmcs::guest_activity_state;
using ehlr_eapis = eapis::intel_x64::exit_handler;

static void
set_vm_entry_interruption_information(const ehlr_eapis::event &event)
{
    auto eii = 0ULL;
    auto deliver_error_code = false;

    // bfdebug_transaction([&](std::string *msg) {
    //     bfdebug_info(0, "set_vm_entry_interruption_information: event", msg);
    //     bfdebug_subnhex(0, "event.vector", event.vector, msg);
    //     bfdebug_subnhex(0, "event.type", event.type, msg);
    //     bfdebug_subnhex(0, "event.len", event.len, msg);
    //     bfdebug_subnhex(0, "event.error_code", event.error_code, msg);
    // });

    if (event.type == entry_irq_type::non_maskable_interrupt) {
        bfalert_info(0, "injecting non_maskable_interrupts is not supported. request ignored");
        return;
    }

    if (event.type == entry_irq_type::hardware_exception) {

        switch (event.vector) {
            case 8:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 17:
                deliver_error_code = true;
                break;
        }
    }

    eii = entry_irq_info::vector::set(eii, event.vector);
    eii = entry_irq_type::set(eii, event.type);
    eii = entry_irq_info::deliver_error_code_bit::set(eii, deliver_error_code);
    eii = entry_irq_info::valid_bit::enable(eii);

    entry_irq_info::set(eii);

    if (deliver_error_code) {
        ::intel_x64::vmcs::vm_entry_exception_error_code::set(event.error_code & 0x7FFF);
    }

    switch (event.type) {
        case entry_irq_type::software_interrupt:
        case entry_irq_type::privileged_software_exception:
        case entry_irq_type::software_exception:
            ::intel_x64::vmcs::vm_entry_instruction_length::set(event.len);
            break;

        default:
            break;
    }
}

void
ehlr_eapis::queue_event(
    vector_type vector, event_type type, instr_len_type len, error_code_type error_code)
{
    m_event_queue.push_back({
        vector,
        type,
        len,
        error_code
    });

    proc_ctls::interrupt_window_exiting::enable();
}

void
ehlr_eapis::inject_event(
    vector_type vector, event_type type, instr_len_type len, error_code_type error_code)
{
    if (guest_irq_state::blocking_by_sti::is_enabled()) {
        return queue_event(vector, type, len, error_code);
    }

    if (type == entry_irq_type::external_interrupt) {

        if (::intel_x64::vmcs::guest_rflags::interrupt_enable_flag::is_disabled()) {
            return queue_event(vector, type, len, error_code);
        }

        if (guest_irq_state::get() != 0) {
            return queue_event(vector, type, len, error_code);
        }
    }

    if (!m_event_queue.empty()) {
        return queue_event(vector, type, len, error_code);
    }

    if (entry_irq_info::valid_bit::is_enabled()) {
        return queue_event(vector, type, len, error_code);
    }

    if (::intel_x64::vmcs::guest_activity_state::get() != ::intel_x64::vmcs::guest_activity_state::active) {
        return queue_event(vector, type, len, error_code);
    }

    set_vm_entry_interruption_information({
        vector,
        type,
        len,
        error_code
    });
}

void
ehlr_eapis::handle_exit__external_interrupt()
{
    auto eii = exit_irq_info::get();

    if (exit_irq_info::valid_bit::is_disabled(eii)) {
        bfalert_info(0, "invalid interruption exit information. interrupt ignored");
        m_vmcs->resume();    /// ****************************************************** There is no longer a need to resume. You should return true instead
    }

    if (exit_irq_info::nmi_unblocking_due_to_iret::is_enabled(eii)) {
        bfalert_info(0, "nmi_unblocking_due_to_iret is unsupported. interrupt ignored");
        m_vmcs->resume();    /// ****************************************************** There is no longer a need to resume. You should return true instead
    }

    inject_event(
        exit_irq_info::vector::get(eii),
        exit_irq_type::get(eii),
        ::intel_x64::vmcs::vm_exit_instruction_length::get(),
        ::intel_x64::vmcs::vm_exit_interruption_error_code::get()
    );

    m_vmcs->resume();    /// ****************************************************** There is no longer a need to resume. You should return true instead
}

void
ehlr_eapis::handle_exit__interrupt_window()
{
    if (m_event_queue.empty()) {
        bfalert_info(0, "event queue empty: interrupt window ignored");
        m_vmcs->resume();    /// ****************************************************** There is no longer a need to resume. You should return true instead
    }

    set_vm_entry_interruption_information(m_event_queue.front());
    m_event_queue.pop_front();

    proc_ctls::interrupt_window_exiting::set(!m_event_queue.empty());
    m_vmcs->resume();    /// ****************************************************** There is no longer a need to resume. You should return true instead
}

void
ehlr_eapis::enable_vmm_exceptions() noexcept
{
    m_tpr_shadow = ::intel_x64::cr8::get();
    ::intel_x64::cr8::set(0x0FU);

    ::x64::rflags::interrupt_enable_flag::enable();
}

void
ehlr_eapis::disable_vmm_exceptions() noexcept
{
    ::x64::rflags::interrupt_enable_flag::disable();
    ::intel_x64::cr8::set(m_tpr_shadow);
}
