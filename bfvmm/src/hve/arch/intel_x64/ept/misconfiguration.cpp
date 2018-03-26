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
    gsl::not_null<vmcs_t *> vmcs, misconfiguration::info_t &info)
{ bfignored(vmcs); bfignored(info); return true; }

misconfiguration::misconfiguration(
    gsl::not_null<eapis::intel_x64::hve *> hve
) :
    m_exit_handler{hve->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::ept_misconfiguration,
        ::handler_delegate_t::create<misconfiguration, &misconfiguration::handle>(this)
    );

    this->add_handler(handler_delegate_t::create<default_handler>());
}

misconfiguration::~misconfiguration()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

void
misconfiguration::add_handler(handler_delegate_t &&d)
{ m_handlers.push_front(std::move(d)); }

void
misconfiguration::dump_log()
{
    if (!m_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "ept misconfiguration log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_log) {
                bfdebug_subnhex(0, "guest virtual address", record.gva, msg);
                bfdebug_subnhex(0, "guest physical address", record.gpa, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }
}

bool
misconfiguration::handle(gsl::not_null<vmcs_t *> vmcs)
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
        "ept::misconfiguration::handle: unhandled ept misconfiguration");
}

}
}
}
