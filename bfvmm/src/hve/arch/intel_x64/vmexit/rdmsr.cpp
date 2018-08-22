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

rdmsr_handler::rdmsr_handler(
    gsl::not_null<apis *> apis
) :
    m_msr_bitmap{apis->msr_bitmap()}
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::rdmsr,
        ::handler_delegate_t::create<rdmsr_handler, &rdmsr_handler::handle>(this)
    );
}

rdmsr_handler::~rdmsr_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
rdmsr_handler::add_handler(
    vmcs_n::value_type msr, const handler_delegate_t &d)
{
#ifndef DISABLE_AUTO_TRAP_ON_ACCESS
    this->trap_on_access(msr);
#endif
    m_handlers[msr].push_front(d);
}

void
rdmsr_handler::trap_on_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0x00000000UL) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
rdmsr_handler::trap_on_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(0, m_msr_bitmap.size() >> 1), 0xFF); }

void
rdmsr_handler::pass_through_access(vmcs_n::value_type msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0x00000000) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
rdmsr_handler::pass_through_all_accesses()
{ gsl::memset(m_msr_bitmap.subspan(0, m_msr_bitmap.size() >> 1), 0x00); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
rdmsr_handler::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "rdmsr_handler log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "msr", record.msr, msg);
            bfdebug_subnhex(0, "val", record.val, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
rdmsr_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{

    // TODO: IMPORTANT!!!
    //
    // We need to create a list of MSRs that are implemented and GP when the
    // MSR is not implemented. We also need to test to make sure the the hardware
    // is enforcing the privilege level of this instruction while the hypervisor
    // is loaded.
    //
    // To fire a GP, we need to add a Bareflank specific exception that can be
    // thrown. The base hypervisor can then trap on this type of exception and
    // have delegates that can be registered to handle the exeption type, which in
    // this case would be the interrupt code that would then inject a GP.
    //

    const auto &hdlrs =
        m_handlers.find(
            vmcs->save_state()->rcx
        );

    if (GSL_LIKELY(hdlrs != m_handlers.end())) {

        struct info_t info = {
            vmcs->save_state()->rcx,
            0,
            false,
            false
        };

        info.val =
            emulate_rdmsr(
                gsl::narrow_cast<::x64::msrs::field_type>(vmcs->save_state()->rcx)
            );

        if (!ndebug && m_log_enabled) {
            add_record(m_log, {
                info.msr, info.val
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    vmcs->save_state()->rax = ((info.val >> 0x00) & 0x00000000FFFFFFFF);
                    vmcs->save_state()->rdx = ((info.val >> 0x20) & 0x00000000FFFFFFFF);
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
    vmcs->save_state()->rdx = 0;

    return advance(vmcs);
}

}
}
