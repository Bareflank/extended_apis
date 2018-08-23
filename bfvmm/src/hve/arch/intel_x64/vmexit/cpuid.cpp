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

cpuid_handler::cpuid_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle>(this)
    );
}

cpuid_handler::~cpuid_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
cpuid_handler::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "cpuid_handler log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "rax_in", record.rax_in, msg);
            bfdebug_subnhex(0, "rbx_in", record.rbx_in, msg);
            bfdebug_subnhex(0, "rcx_in", record.rcx_in, msg);
            bfdebug_subnhex(0, "rdx_in", record.rdx_in, msg);
            bfdebug_subnhex(0, "rax_out", record.rax_out, msg);
            bfdebug_subnhex(0, "rbx_out", record.rbx_out, msg);
            bfdebug_subnhex(0, "rcx_out", record.rcx_out, msg);
            bfdebug_subnhex(0, "rdx_out", record.rdx_out, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    const auto &hdlrs =
        m_handlers.find(vmcs->save_state()->rax);

    if (hdlrs != m_handlers.end()) {

        auto ret =
            ::x64::cpuid::get(
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rax),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rbx),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rcx),
                gsl::narrow_cast<::x64::cpuid::field_type>(vmcs->save_state()->rdx)
            );

        struct info_t info = {
            ret.rax,
            ret.rbx,
            ret.rcx,
            ret.rdx,
            false,
            false
        };

        if (!ndebug && m_log_enabled) {
            add_record(m_log, {
                vmcs->save_state()->rax,
                vmcs->save_state()->rbx,
                vmcs->save_state()->rcx,
                vmcs->save_state()->rdx,
                info.rax, info.rbx, info.rcx, info.rdx
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    vmcs->save_state()->rax = set_bits(vmcs->save_state()->rax, 0x00000000FFFFFFFFULL, info.rax);
                    vmcs->save_state()->rbx = set_bits(vmcs->save_state()->rbx, 0x00000000FFFFFFFFULL, info.rbx);
                    vmcs->save_state()->rcx = set_bits(vmcs->save_state()->rcx, 0x00000000FFFFFFFFULL, info.rcx);
                    vmcs->save_state()->rdx = set_bits(vmcs->save_state()->rdx, 0x00000000FFFFFFFFULL, info.rdx);
                }

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

    return false;
}

}
}
