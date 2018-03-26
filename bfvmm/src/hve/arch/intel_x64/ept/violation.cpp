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
namespace ept
{

static bool
default_handler(
    gsl::not_null<vmcs_t *> vmcs, violation::info_t &info)
{ bfignored(vmcs); bfignored(info); return true; }

violation::violation(
    gsl::not_null<eapis::intel_x64::hve *> hve
) :
    m_exit_handler{hve->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::ept_violation,
        ::handler_delegate_t::create<violation, &violation::handle>(this)
    );

    this->add_read_handler(handler_delegate_t::create<default_handler>());
    this->add_write_handler(handler_delegate_t::create<default_handler>());
    this->add_execute_handler(handler_delegate_t::create<default_handler>());
}

violation::~violation()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

void
violation::add_read_handler(handler_delegate_t &&d)
{ m_read_handlers.push_front(std::move(d)); }

void
violation::add_write_handler(handler_delegate_t &&d)
{ m_write_handlers.push_front(std::move(d)); }

void
violation::add_execute_handler(handler_delegate_t &&d)
{ m_execute_handlers.push_front(std::move(d)); }

void
violation::dump_log()
{
    if (!m_read_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "ept read violation log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_read_log) {
                bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
                bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }

    if (!m_write_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "ept write violation log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_write_log) {
                bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
                bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }

    if (!m_execute_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "ept execute violation log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_execute_log) {
                bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
                bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }
}

bool
violation::handle(gsl::not_null<vmcs_t *> vmcs)
{
    namespace ept_violation = vmcs_n::exit_qualification::ept_violation;

    struct info_t info = {
        vmcs_n::guest_linear_address::get(),
        vmcs_n::guest_physical_address::get(),
        false
    };

    if (ept_violation::data_read::is_enabled()) {
        return handle_read(vmcs, info);
    }

    if (ept_violation::data_write::is_enabled()) {
        return handle_write(vmcs, info);
    }

    if (ept_violation::instruction_fetch::is_enabled()) {
        return handle_execute(vmcs, info);
    }

    throw std::runtime_error("ept::violation::handle: unhandled ept violation");
}

bool
violation::handle_read(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_read_log, {info.gva, info.gpa});
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
        "ept::violation: unhandled ept read violation");
}

bool
violation::handle_write(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_write_log, {info.gva, info.gpa});
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
        "ept::violation: unhandled ept write violation");
}

bool
violation::handle_execute(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    if (!ndebug && m_log_enabled) {
        add_record(m_execute_log, {info.gva, info.gpa});
    }

    for (const auto &d : m_execute_handlers) {
        if (d(vmcs, info)) {

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    throw std::runtime_error("ept::violation: unhandled ept execute violation");
}

}
}
}
