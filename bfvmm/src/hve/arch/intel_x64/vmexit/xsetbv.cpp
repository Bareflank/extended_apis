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

xsetbv_handler::xsetbv_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state)
{
    using namespace vmcs_n;
    bfignored(eapis_vcpu_global_state);

    apis->add_handler(
        vmcs_n::exit_reason::basic_exit_reason::xsetbv,
        ::handler_delegate_t::create<xsetbv_handler, &xsetbv_handler::handle>(this)
    );
}

xsetbv_handler::~xsetbv_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
xsetbv_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
xsetbv_handler::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "xsetbv log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "val", record.val, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
xsetbv_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        0,
        false,
        false
    };

    info.val |= ((vmcs->save_state()->rax & 0x00000000FFFFFFFF) << 0x00);
    info.val |= ((vmcs->save_state()->rdx & 0x00000000FFFFFFFF) << 0x20);

    if (!ndebug && m_log_enabled) {
        add_record(m_log, {
            info.val
        });
    }

    for (const auto &d : m_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        ::intel_x64::xcr0::set(info.val);
    }

    if (!info.ignore_advance) {
        return advance(vmcs);
    }

    return true;
}

}
}
