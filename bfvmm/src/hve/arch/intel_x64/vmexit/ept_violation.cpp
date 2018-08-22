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

ept_violation_handler::ept_violation_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::ept_violation,
        ::handler_delegate_t::create<ept_violation_handler, &ept_violation_handler::handle>(this)
    );
}

ept_violation_handler::~ept_violation_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
ept_violation_handler::add_read_handler(
    const handler_delegate_t &d)
{ m_read_handlers.push_front(d); }

void
ept_violation_handler::add_write_handler(
    const handler_delegate_t &d)
{ m_write_handlers.push_front(d); }

void
ept_violation_handler::add_execute_handler(
    const handler_delegate_t &d)
{ m_execute_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
ept_violation_handler::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "ept violation log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
            bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            bfdebug_subnhex(0, "exit qualification", record.exit_qualification, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_violation_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n;
    auto qual = exit_qualification::ept_violation::get();

    struct info_t info = {
        guest_linear_address::get(),
        guest_physical_address::get(),
        qual,
        true
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_log, {info.gva, info.gpa, info.exit_qualification});
    }

    if (exit_qualification::ept_violation::data_read::is_enabled(qual)) {
        return handle_read(vmcs, info);
    }

    if (exit_qualification::ept_violation::data_write::is_enabled(qual)) {
        return handle_write(vmcs, info);
    }

    if (exit_qualification::ept_violation::instruction_fetch::is_enabled(qual)) {
        return handle_execute(vmcs, info);
    }

    throw std::runtime_error(
        "ept_violation_handler::handle: unhandled ept violation"
    );
}

bool
ept_violation_handler::handle_read(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    for (const auto &d : m_read_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept read violation"
    );
}

bool
ept_violation_handler::handle_write(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    for (const auto &d : m_write_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept write violation"
    );
}

bool
ept_violation_handler::handle_execute(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    for (const auto &d : m_execute_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept execute violation"
    );
}

}
}
