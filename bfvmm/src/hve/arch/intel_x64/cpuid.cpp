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

cpuid::cpuid(gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_exit_handler{hve->exit_handler()}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<cpuid, &cpuid::handle>(this)
    );
}

cpuid::~cpuid()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// CR0
// -----------------------------------------------------------------------------

void cpuid::add_handler(
    leaf_t leaf, subleaf_t subleaf, handler_delegate_t &&d)
{ m_handlers[ {leaf, subleaf}].push_front(std::move(d)); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
cpuid::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "cpuid log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "leaf", record.leaf, msg);
            bfdebug_subnhex(0, "subleaf", record.subleaf, msg);
            bfdebug_subnhex(0, "rax", record.rax, msg);
            bfdebug_subnhex(0, "rbx", record.rbx, msg);
            bfdebug_subnhex(0, "rcx", record.rcx, msg);
            bfdebug_subnhex(0, "rdx", record.rdx, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid::handle(gsl::not_null<vmcs_t *> vmcs)
{
    const auto &hdlrs = m_handlers.find({
        vmcs->save_state()->rax, vmcs->save_state()->rcx
    });

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

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
                vmcs->save_state()->rcx,
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

#ifndef SECURE_MODE
    return false;
#endif

    vmcs->save_state()->rax = 0;
    vmcs->save_state()->rbx = 0;
    vmcs->save_state()->rcx = 0;
    vmcs->save_state()->rdx = 0;

    return advance(vmcs);
}

}
}
