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
#include <hve/arch/intel_x64/vcpu.h>

namespace eapis
{
namespace intel_x64
{

monitor_trap_handler::monitor_trap_handler(
    gsl::not_null<eapis::intel_x64::vcpu *> vcpu
) :
    m_exit_handler{vcpu->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::monitor_trap_flag,
        ::handler_delegate_t::create<monitor_trap_handler, &monitor_trap_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Monitor Trap
// -----------------------------------------------------------------------------

void
monitor_trap_handler::add_handler(handler_delegate_t &&d)
{ m_handlers.push_front(d); }

void
monitor_trap_handler::enable()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
monitor_trap_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n;

    struct info_t info = {
        false
    };

    for (const auto &d : m_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    if (!info.ignore_clear) {
        primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
    }

    return true;
}

}
}
