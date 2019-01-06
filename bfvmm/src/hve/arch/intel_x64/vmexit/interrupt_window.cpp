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

interrupt_window_handler::interrupt_window_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::interrupt_window,
        ::handler_delegate_t::create<interrupt_window_handler, &interrupt_window_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
interrupt_window_handler::queue_external_interrupt(uint64_t vector)
{
    // Note:
    //
    // There are two ways to handle injection. Currently, we inject using an
    // interrupt window. This means that an interrupt is always queued, and it
    // is only injected when the VM has an open window. The downside to this
    // approach is that when this function is called, it is possible that the
    // window is actually open, which means that we needlessly generate an
    // extra VM exit.
    //
    // The other approach is to check to see if the window is open and inject.
    // The issue with this approach is that we always have to check to see if
    // the window is open which is expensive, and then we have to have a lot of
    // extra logic to handle injecting without overwritting existing
    // interrupts, getting interrupts out of order, etc... There are a lot
    // more edge cases. The beauty of our current approach is that our window
    // handler is the only thing that can inject an interrupt, which is
    // mutually exclusive with queueing (as queueing occurs on any VM exit
    // other than our window) which means there are no race conditions, or
    // overwritting, etc... And, we do not have to make several vmreads per
    // injection. Since we leverage vpid, a VM exit that occurs before an entry
    // has a minimum performance hit as the VMM is still in the cache so this
    // approach is both reliable and performant.
    //
    // Also note that our approach also works fine with exceptions. Exceptions
    // do not need to be queued since they cannot be blocked. This means that
    // exceptions can be injected on any VM exit without fear of overwritting
    // an external interrupt as they are only injected on an open window exit
    // which once again, will not attempt to inject an exception at the same
    // time since that code is managed here, and is very small.
    //

    this->enable_exiting();
    m_interrupt_queue.push(vector);
}

void
interrupt_window_handler::inject_exception(uint64_t vector, uint64_t ec)
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;
    using namespace info_n::interruption_type;

    uint64_t info = 0;

    info_n::vector::set(info, vector);
    info_n::interruption_type::set(info, hardware_exception);
    info_n::valid_bit::enable(info);

    switch(vector) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            info_n::deliver_error_code_bit::enable(info);
            vmcs_n::vm_entry_exception_error_code::set(ec);
            break;

        default:
            break;
    }

    info_n::set(info);
}

void
interrupt_window_handler::inject_external_interrupt(uint64_t vector)
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;
    using namespace info_n::interruption_type;

    uint64_t info = 0;

    info_n::vector::set(info, vector);
    info_n::interruption_type::set(info, external_interrupt);
    info_n::valid_bit::enable(info);

    info_n::set(info);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
interrupt_window_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);
    this->inject_external_interrupt(m_interrupt_queue.pop());

    if (m_interrupt_queue.empty()) {
        this->disable_exiting();
    }

    return true;
}

// -----------------------------------------------------------------------------
// Private
// -----------------------------------------------------------------------------

void
interrupt_window_handler::enable_exiting()
{
    using namespace vmcs_n;

    if (m_enabled == false) {
        primary_processor_based_vm_execution_controls::interrupt_window_exiting::enable();
        m_enabled = true;
    }
}

void
interrupt_window_handler::disable_exiting()
{
    using namespace vmcs_n;

    if (m_enabled == true) {
        primary_processor_based_vm_execution_controls::interrupt_window_exiting::disable();
        m_enabled = false;
    }
}

}
