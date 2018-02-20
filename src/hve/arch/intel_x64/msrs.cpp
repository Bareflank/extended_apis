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
#include <hve/arch/intel_x64/msrs.h>

#include <intrinsics.h>
#include <bfvmm/memory_manager/memory_manager.h>

namespace eapis
{
namespace intel_x64
{

msrs::msrs(
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler)
:
    m_exit_handler{exit_handler}
{
    using namespace ::intel_x64::vmcs;

    m_msr_bitmap = std::make_unique<uint8_t[]>(::x64::page_size);
    m_msr_bitmap_view = gsl::make_span(m_msr_bitmap, ::x64::page_size);

    address_of_msr_bitmap::set(g_mm->virtptr_to_physint(m_msr_bitmap.get()));
    primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();

    m_exit_handler->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::rdmsr,
        handler_delegate_t::create<msrs, &msrs::handle_rdmsr>(this)
    );

    m_exit_handler->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::wrmsr,
        handler_delegate_t::create<msrs, &msrs::handle_wrmsr>(this)
    );
}

msrs::~msrs()
{
#ifndef NDEBUG
    if(m_log_enabled) {
        dump_log();
    }
#endif
}

// -----------------------------------------------------------------------------
// RDMSR
// -----------------------------------------------------------------------------

void
msrs::add_rdmsr_handler(msr_t msr, rdmsr_handler_delegate_t &&d)
{ m_rdmsr_handlers[msr].push_front(std::move(d)); }

void
msrs::trap_on_rdmsr_access(msr_t msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap_view, (msr - 0x00000000UL) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap_view, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
msrs::trap_on_all_rdmsr_accesses()
{ memset(&m_msr_bitmap_view[0], 0xFF, ::x64::page_size >> 1); }

void
msrs::pass_through_rdmsr_access(msr_t msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap_view, (msr - 0x00000000) + 0);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap_view, (msr - 0xC0000000UL) + 0x2000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
msrs::pass_through_all_rdmsr_accesses()
{ memset(&m_msr_bitmap_view[0], 0x0, ::x64::page_size >> 1); }

// -----------------------------------------------------------------------------
// WRMSR
// -----------------------------------------------------------------------------

void
msrs::add_wrmsr_handler(msr_t msr, wrmsr_handler_delegate_t &&d)
{ m_wrmsr_handlers[msr].push_front(std::move(d)); }

void
msrs::trap_on_wrmsr_access(msr_t msr)
{
    if (msr <= 0x00001FFFUL) {
        return set_bit(m_msr_bitmap_view, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return set_bit(m_msr_bitmap_view, (msr - 0xC0000000UL) + 0x6000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
msrs::trap_on_all_wrmsr_accesses()
{ memset(&m_msr_bitmap_view[2048], 0xFF, ::x64::page_size >> 1); }

void
msrs::pass_through_wrmsr_access(msr_t msr)
{
    if (msr <= 0x00001FFFUL) {
        return clear_bit(m_msr_bitmap_view, (msr - 0x00000000UL) + 0x4000);
    }

    if (msr >= 0xC0000000UL && msr <= 0xC0001FFFUL) {
        return clear_bit(m_msr_bitmap_view, (msr - 0xC0000000UL) + 0x6000);
    }

    throw std::runtime_error("invalid msr: " + std::to_string(msr));
}

void
msrs::pass_through_all_wrmsr_accesses()
{ memset(&m_msr_bitmap_view[2048], 0x0, ::x64::page_size >> 1); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

#ifndef NDEBUG

void
msrs::enable_log()
{ m_log_enabled = true; }

void
msrs::disable_log()
{ m_log_enabled = false; }

void
msrs::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "msrs log", msg);
        bfdebug_brk2(0, msg);

        bfdebug_info(0, "rdmsr log", msg);
        for(const auto &msr : m_rdmsr_log) {
            for(const auto &record : msr.second) {
                bfdebug_subnhex(0, bfn::to_string(msr.first, 16).c_str(), record, msg);
            }
        }

        bfdebug_info(0, "wrmsr log", msg);
        for(const auto &msr : m_wrmsr_log) {
            for(const auto &record : msr.second) {
                bfdebug_subnhex(0, bfn::to_string(msr.first, 16).c_str(), record, msg);
            }
        }

        bfdebug_lnbr(0, msg);
    });
}

#endif

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
msrs::handle_rdmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(
        vmcs->save_state()->rcx
    );

    auto val = emulate_rdmsr(
        msr
    );

    const auto &hdlrs = m_rdmsr_handlers.find(
        msr
    );

#ifndef NDEBUG
    if (m_log_enabled) {
        m_rdmsr_log[msr].push_back(val);
    }
#endif

    if (GSL_LIKELY(hdlrs != m_rdmsr_handlers.end())) {

        struct info_t info = {
            msr,
            val
        };

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {
                vmcs->save_state()->rax = ((info.val >> 0x00) & 0x00000000FFFFFFFF);
                vmcs->save_state()->rdx = ((info.val >> 0x20) & 0x00000000FFFFFFFF);
                return advance(vmcs);
            }
        }
    }

    return false;
}

bool
msrs::handle_wrmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    auto msr = gsl::narrow_cast<::x64::msrs::field_type>(
        vmcs->save_state()->rcx
    );

    auto val =
        ((vmcs->save_state()->rax & 0x00000000FFFFFFFF) << 0x00) |
        ((vmcs->save_state()->rdx & 0x00000000FFFFFFFF) << 0x20);

    const auto &hdlrs = m_wrmsr_handlers.find(
        msr
    );

#ifndef NDEBUG
    if (m_log_enabled) {
        m_wrmsr_log[msr].push_back(val);
    }
#endif

    if (GSL_LIKELY(hdlrs != m_wrmsr_handlers.end())) {

        struct info_t info = {
            msr,
            val
        };

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {
                emulate_wrmsr(msr, info.val);
                return advance(vmcs);
            }
        }
    }

    return false;
}

}
}
