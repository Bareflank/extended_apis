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
#include <hve/arch/intel_x64/monitor_trap.h>

namespace eapis
{
namespace intel_x64
{

static bool
default_handler(
    gsl::not_null<vmcs_t *> vmcs, monitor_trap::info_t &info)
{ bfignored(vmcs); bfignored(info); return true; }

monitor_trap::monitor_trap(gsl::not_null<exit_handler_t *> exit_handler) :
    m_exit_handler{exit_handler}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::monitor_trap_flag,
        ::handler_delegate_t::create<monitor_trap, &monitor_trap::handle>(this)
    );

    this->add_handler(
        handler_delegate_t::create<default_handler>()
    );
}

// -----------------------------------------------------------------------------
// Monitor Trap
// -----------------------------------------------------------------------------

void
monitor_trap::add_handler(handler_delegate_t &&d)
{ m_handlers.push_front(std::move(d)); }

void
monitor_trap::enable()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
monitor_trap::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n;

    struct info_t info = {
        false
    };

    for (const auto &d : m_handlers) {
        if (d(vmcs, info)) {

            if(!info.ignore_clear) {
                primary_processor_based_vm_execution_controls::monitor_trap_flag::disable();
            }

            return true;
        }
    }

    return false;
}

}
}
