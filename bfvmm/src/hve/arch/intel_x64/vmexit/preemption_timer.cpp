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

preemption_timer_handler::preemption_timer_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::preemption_timer_expired,
        ::handler_delegate_t::create <
        preemption_timer_handler, &preemption_timer_handler::handle > (this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
preemption_timer_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

void
preemption_timer_handler::enable_exiting()
{
    using namespace ::intel_x64::vmcs;

    pin_based_vm_execution_controls::activate_preemption_timer::enable();
    vm_exit_controls::save_preemption_timer_value::enable();
}

void
preemption_timer_handler::disable_exiting()
{
    using namespace ::intel_x64::vmcs;

    vm_exit_controls::save_preemption_timer_value::disable();
    pin_based_vm_execution_controls::activate_preemption_timer::disable();
}

void
preemption_timer_handler::set_timer(value_t val)
{
    using namespace ::intel_x64::vmcs;
    preemption_timer_value::set(val);
}

preemption_timer_handler::value_t
preemption_timer_handler::get_timer() const
{
    using namespace ::intel_x64::vmcs;
    return preemption_timer_value::get();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
preemption_timer_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    for (const auto &d : m_handlers) {
        if (d(vcpu)) {
            return true;
        }
    }

    throw std::runtime_error(
        "preemption_timer_handler::handle: unhandled vmx-preemption timer exit"
    );
}

}
