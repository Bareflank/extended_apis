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
#include <hve/arch/intel_x64/drs.h>

namespace eapis
{
namespace intel_x64
{

static bool
default_handler(
    gsl::not_null<vmcs_t *> vmcs, drs::info_t &info)
{ bfignored(vmcs); bfignored(info); return true; }

drs::drs(gsl::not_null<exit_handler_t *> exit_handler) :
    m_exit_handler{exit_handler}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::mov_dr,
        ::handler_delegate_t::create<drs, &drs::handle_drs>(this)
    );

    this->add_handler(
        handler_delegate_t::create<default_handler>()
    );
}

drs::~drs()
{
    if(!ndebug && this->is_logging_enabled()) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// DR7
// -----------------------------------------------------------------------------

void
drs::add_handler(handler_delegate_t &&d)
{ m_handlers.push_front(std::move(d)); }

void
drs::enable_wrdr7_trapping()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::mov_dr_exiting::enable();
}

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
drs::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "dr7 log", msg);
        bfdebug_brk2(0, msg);

        for(const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "val", record.val, msg);
            bfdebug_subbool(0, "out", record.out, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
drs::handle_drs(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        this->emulate_rdgpr(vmcs),
        false,
        false
    };

    if (!ndebug && this->is_logging_enabled()) {
        add_record(m_log, {
            info.val, false
        });
    }

    for (const auto &d : m_handlers) {
        if (d(vmcs, info)) {

            if (!ndebug && this->is_logging_enabled()) {
                add_record(m_log, {
                    info.val, true
                });
            }

            if(!info.ignore_write) {
                vmcs_n::guest_dr7::set(info.val & 0x00000000FFFFFFFF);
            }

            if (!info.ignore_advance) {
                return advance(vmcs);
            }

            return true;
        }
    }

    return false;
}

}
}
