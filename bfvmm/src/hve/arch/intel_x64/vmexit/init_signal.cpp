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
#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

init_signal_handler::init_signal_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::init_signal,
        ::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle>(this)
    );
}

init_signal_handler::~init_signal_handler()
{ }

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
init_signal_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
init_signal_handler::dump_log()
{ }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
init_signal_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    for (const auto &d : m_handlers) {
        if (d(vmcs)) {
            return true;
        }
    }

    return false;
}

}
}
