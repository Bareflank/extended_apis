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

#include <bfintrinsics/include/intrinsics.h>
#include <hve/arch/intel_x64/exit_handler/exit_handler.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;
using namespace primary_processor_based_vm_execution_controls;

static void
set_vm_entry_interruption_information(const exit_handler_intel_x64_eapis::event &event)
{
    using namespace vm_entry_interruption_information;

    auto eii = 0ULL;
    auto deliver_error_code = false;

    // bfdebug_transaction([&](std::string *msg) {
    //     bfdebug_info(0, "set_vm_entry_interruption_information: event", msg);
    //     bfdebug_subnhex(0, "event.vector", event.vector, msg);
    //     bfdebug_subnhex(0, "event.type", event.type, msg);
    //     bfdebug_subnhex(0, "event.len", event.len, msg);
    //     bfdebug_subnhex(0, "event.error_code", event.error_code, msg);
    // });

    if (event.type == interruption_type::non_maskable_interrupt) {
        bfalert_info(0, "injecting non_maskable_interrupts is not supported. request ignored");
        return;
    }

    if (event.type == interruption_type::hardware_exception) {

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

    eii = vm_entry_interruption_information::vector::set(eii, event.vector);
    eii = vm_entry_interruption_information::interruption_type::set(eii, event.type);
    eii = vm_entry_interruption_information::deliver_error_code_bit::set(eii, deliver_error_code);
    eii = vm_entry_interruption_information::valid_bit::enable(eii);

    vm_entry_interruption_information::set(eii);

    if (deliver_error_code) {
        vm_entry_exception_error_code::set(event.error_code & 0x7FFF);
    }

    switch (event.type) {
        case interruption_type::software_interrupt:
        case interruption_type::privileged_software_exception:
        case interruption_type::software_exception:
            vm_entry_instruction_length::set(event.len);
            break;

        default:
            break;
    }
}

void
exit_handler_intel_x64_eapis::queue_event(
    vector_type vector, event_type type, instr_len_type len, error_code_type error_code)
{
    m_event_queue.push_back({
        vector,
        type,
        len,
        error_code
    });

    interrupt_window_exiting::enable();
}

void
exit_handler_intel_x64_eapis::inject_event(
    vector_type vector, event_type type, instr_len_type len, error_code_type error_code)
{
    if (vmcs::guest_interruptibility_state::blocking_by_sti::is_enabled()) {
        return queue_event(vector, type, len, error_code);
    }

    if (type == vm_entry_interruption_information::interruption_type::external_interrupt) {

        if (guest_rflags::interrupt_enable_flag::is_disabled()) {
            return queue_event(vector, type, len, error_code);
        }

        if (vmcs::guest_interruptibility_state::get() != 0) {
            return queue_event(vector, type, len, error_code);
        }
    }

    if (!m_event_queue.empty()) {
        return queue_event(vector, type, len, error_code);
    }

    if (vm_entry_interruption_information::valid_bit::is_enabled()) {
        return queue_event(vector, type, len, error_code);
    }

    if (vmcs::guest_activity_state::get() != vmcs::guest_activity_state::active) {
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
exit_handler_intel_x64_eapis::handle_exit__external_interrupt()
{
    auto eii = vm_exit_interruption_information::get();

    if (vm_exit_interruption_information::valid_bit::is_disabled(eii)) {
        bfalert_info(0, "invalid interruption exit information. interrupt ignored");
        this->resume();
    }

    if (vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_enabled(eii)) {
        bfalert_info(0, "nmi_unblocking_due_to_iret is unsupported. interrupt ignored");
        this->resume();
    }

    inject_event(
        vm_exit_interruption_information::vector::get(eii),
        vm_exit_interruption_information::interruption_type::get(eii),
        vm_exit_instruction_length::get(),
        vm_exit_interruption_error_code::get()
    );

    this->resume();
}

void
exit_handler_intel_x64_eapis::handle_exit__interrupt_window()
{
    if (m_event_queue.empty()) {
        bfalert_info(0, "event queue empty: interrupt window ignored");
        this->resume();
    }

    set_vm_entry_interruption_information(m_event_queue.front());
    m_event_queue.pop_front();

    interrupt_window_exiting::set(!m_event_queue.empty());
    this->resume();
}

void
exit_handler_intel_x64_eapis::enable_vmm_exceptions() noexcept
{
    m_tpr_shadow = cr8::get();
    cr8::set(0x0FU);

    rflags::interrupt_enable_flag::enable();
}

void
exit_handler_intel_x64_eapis::disable_vmm_exceptions() noexcept
{
    rflags::interrupt_enable_flag::disable();
    cr8::set(m_tpr_shadow);
}
