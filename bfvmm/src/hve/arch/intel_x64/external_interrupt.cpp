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
#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/ept/helpers.h>

namespace eapis
{
namespace intel_x64
{

external_interrupt::external_interrupt(gsl::not_null<eapis::intel_x64::hve *> hve)
    :
    m_log{{0}}
{
    using namespace vmcs_n;

    hve->exit_handler()->add_handler(
        exit_reason::basic_exit_reason::external_interrupt,
        ::handler_delegate_t::create<external_interrupt, &external_interrupt::handle>(this)
    );
}

external_interrupt::~external_interrupt()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

void
external_interrupt::add_handler(
    vmcs_n::value_type vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(d); }

void
external_interrupt::enable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::enable();
}

void
external_interrupt::disable_exiting()
{
    vmcs_n::pin_based_vm_execution_controls::external_interrupt_exiting::disable();
    vmcs_n::vm_exit_controls::acknowledge_interrupt_on_exit::disable();
}

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
external_interrupt::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "External interrupt counts", msg);
        bfdebug_brk2(0, msg);

        for (auto i = 0U; i < 256U; ++i) {
            if (m_log.at(i) > 0U) {
                bfdebug_subnhex(0, std::to_string(i).c_str(), m_log.at(i), msg);
            }
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handle
// -----------------------------------------------------------------------------

bool
external_interrupt::handle(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        vmcs_n::vm_exit_interruption_information::vector::get()
    };

    if (!ndebug && m_log_enabled) {
        m_log.at(info.vector)++;
    }

    for (const auto &d : m_handlers.at(info.vector)) {
        if (d(vmcs, info)) {
            return true;
        }
    }

    throw std::runtime_error("Unhandled interrupt vector: "
                             + std::to_string(info.vector));
}

}
}
