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

namespace eapis
{
namespace intel_x64
{

ept_violation::ept_violation(
    gsl::not_null<eapis::intel_x64::hve *> hve
) :
    m_exit_handler{hve->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::ept_violation,
        ::handler_delegate_t::create<ept_violation, &ept_violation::handle>(this)
    );
}

ept_violation::~ept_violation()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

void
ept_violation::add_read_handler(handler_delegate_t &&d)
{ m_read_handlers.push_front(d); }

void
ept_violation::add_write_handler(handler_delegate_t &&d)
{ m_write_handlers.push_front(d); }

void
ept_violation::add_execute_handler(handler_delegate_t &&d)
{ m_execute_handlers.push_front(d); }

void
ept_violation::dump_log()
{
    if (!m_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "ept violation log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_log) {

                if (vmcs_n::exit_qualification::ept_violation::data_read::is_enabled(record.exit_qualification)) {
                    bfdebug_info(0, "data read record", msg);
                }

                if (vmcs_n::exit_qualification::ept_violation::data_write::is_enabled(record.exit_qualification)) {
                    bfdebug_info(0, "data write record", msg);
                }

                if (vmcs_n::exit_qualification::ept_violation::instruction_fetch::is_enabled(record.exit_qualification)) {
                    bfdebug_info(0, "instruction fetch record", msg);
                }

                bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
                bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }
}

bool
ept_violation::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n;
    auto qual = exit_qualification::ept_violation::get();
    auto read_access = exit_qualification::ept_violation::data_read::is_enabled(qual);
    auto write_access = exit_qualification::ept_violation::data_write::is_enabled(qual);
    auto execute_access = exit_qualification::ept_violation::instruction_fetch::is_enabled(qual);

    struct info_t info = {
        guest_linear_address::get(),
        guest_physical_address::get(),
        qual,
        false
    };

    if (read_access) {
        return handle_read(vmcs, info);
    }

    if (write_access) {
        return handle_write(vmcs, info);
    }

    if (execute_access) {
        return handle_execute(vmcs, info);
    }

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "ept_violation::handle: unhandled ept violation", msg);
        bfdebug_brk2(0, msg);

        bfdebug_subnhex(0, "guest virtual address", info.gva, msg);
        bfdebug_subnhex(0, "guest physical address", info.gpa, msg);
        bfdebug_subnhex(0, "exit qualification", info.exit_qualification, msg);
        bfdebug_subbool(0, "read access", read_access, msg);
        bfdebug_subbool(0, "write access", write_access, msg);
        bfdebug_subbool(0, "execute access", execute_access, msg);

        bfdebug_lnbr(0, msg);
    });

    throw std::runtime_error("ept_violation::handle: unhandled ept violation");
}

bool
ept_violation::handle_read(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_log, {info.gva, info.gpa, info.exit_qualification});
    }

    for (const auto &d : m_read_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_violation: unhandled ept read violation");
}

bool
ept_violation::handle_write(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_log, {info.gva, info.gpa, info.exit_qualification});
    }

    for (const auto &d : m_write_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_violation: unhandled ept write violation");
}

bool
ept_violation::handle_execute(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_log, {info.gva, info.gpa, info.exit_qualification});
    }

    for (const auto &d : m_execute_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error("ept_violation: unhandled ept execute violation");
}

}
}
