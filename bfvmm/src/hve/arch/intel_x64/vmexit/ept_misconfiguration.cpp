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

ept_misconfiguration_handler::ept_misconfiguration_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::ept_misconfiguration,
        ::handler_delegate_t::create<ept_misconfiguration_handler, &ept_misconfiguration_handler::handle>(this)
    );
}

ept_misconfiguration_handler::~ept_misconfiguration_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
ept_misconfiguration_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
ept_misconfiguration_handler::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "ept misconfiguration log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
            bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_misconfiguration_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        vmcs_n::guest_linear_address::get(),
        vmcs_n::guest_physical_address::get(),
        false
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_log, {info.gva, info.gpa});
    }

    for (const auto &d : m_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_misconfiguration_handler::handle: unhandled ept misconfiguration"
    );
}

}
}
