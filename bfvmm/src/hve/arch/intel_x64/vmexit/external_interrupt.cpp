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

external_interrupt_handler::external_interrupt_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::external_interrupt,
        ::handler_delegate_t::create<external_interrupt_handler, &external_interrupt_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
external_interrupt_handler::add_handler(
    const handler_delegate_t &d)
{ m_handlers.push_front(d); }

void
external_interrupt_handler::enable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::enable();
}

void
external_interrupt_handler::disable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::disable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::disable();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
external_interrupt_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    struct info_t info = {
        vmcs_n::vm_exit_interruption_information::vector::get()
    };

    for (const auto &d : m_handlers) {
        if (d(vcpu, info)) {
            return true;
        }
    }

    throw std::runtime_error(
        "Unhandled interrupt vector: " + std::to_string(info.vector)
    );
}

}
