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
#include <hve/arch/intel_x64/crs.h>

namespace eapis
{
namespace intel_x64
{

static bool
default_handler(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs, crs::info_t &info)
{ bfignored(vmcs); bfignored(info); return false; }

crs::crs(
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler)
:
    m_exit_handler{exit_handler}
{
    m_exit_handler->add_handler(
        ::intel_x64::vmcs::exit_reason::basic_exit_reason::control_register_accesses,
        handler_delegate_t::create<crs, &crs::handle_crs>(this)
    );

    this->add_wrcr0_handler(
        wrcr0_handler_delegate_t::create<default_handler>()
    );

    this->add_rdcr3_handler(
        rdcr3_handler_delegate_t::create<default_handler>()
    );

    this->add_wrcr3_handler(
        wrcr3_handler_delegate_t::create<default_handler>()
    );

    this->add_wrcr4_handler(
        wrcr4_handler_delegate_t::create<default_handler>()
    );

    this->add_rdcr8_handler(
        rdcr8_handler_delegate_t::create<default_handler>()
    );

    this->add_wrcr8_handler(
        wrcr8_handler_delegate_t::create<default_handler>()
    );
}

crs::~crs()
{
#ifndef NDEBUG
    if(m_log_enabled) {
        dump_log();
    }
#endif
}

// -----------------------------------------------------------------------------
// CR0
// -----------------------------------------------------------------------------

void
crs::add_wrcr0_handler(wrcr0_handler_delegate_t &&d)
{ m_wrcr0_handlers.push_front(std::move(d)); }

void
crs::add_rdcr3_handler(rdcr3_handler_delegate_t &&d)
{ m_rdcr3_handlers.push_front(std::move(d)); }

void
crs::add_wrcr3_handler(wrcr3_handler_delegate_t &&d)
{ m_wrcr3_handlers.push_front(std::move(d)); }

void
crs::add_wrcr4_handler(wrcr4_handler_delegate_t &&d)
{ m_wrcr4_handlers.push_front(std::move(d)); }

void
crs::add_rdcr8_handler(rdcr8_handler_delegate_t &&d)
{ m_rdcr8_handlers.push_front(std::move(d)); }

void
crs::add_wrcr8_handler(wrcr8_handler_delegate_t &&d)
{ m_wrcr8_handlers.push_front(std::move(d)); }

void
crs::enable_wrcr0_trapping(mask_t mask, shadow_t shadow)
{
    ::intel_x64::vmcs::cr0_guest_host_mask::set(mask);
    ::intel_x64::vmcs::cr0_read_shadow::set(shadow);
}

void
crs::enable_rdcr3_trapping()
{
    using namespace ::intel_x64::vmcs;
    primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
}

void
crs::enable_wrcr3_trapping()
{
    using namespace ::intel_x64::vmcs;
    primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
}

void
crs::enable_wrcr4_trapping(mask_t mask, shadow_t shadow)
{
    ::intel_x64::vmcs::cr4_guest_host_mask::set(mask);
    ::intel_x64::vmcs::cr4_read_shadow::set(shadow);
}

void
crs::enable_rdcr8_trapping()
{
    using namespace ::intel_x64::vmcs;
    primary_processor_based_vm_execution_controls::cr8_store_exiting::enable();
}

void
crs::enable_wrcr8_trapping()
{
    using namespace ::intel_x64::vmcs;
    primary_processor_based_vm_execution_controls::cr8_load_exiting::enable();
}

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

#ifndef NDEBUG

void
crs::enable_log()
{ m_log_enabled = true; }

void
crs::disable_log()
{ m_log_enabled = false; }

void
crs::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "crs log", msg);
        bfdebug_brk2(0, msg);

        bfdebug_info(0, "wrcr0 log", msg);
        for(const auto &val : m_wrcr0_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_info(0, "rdcr3 log", msg);
        for(const auto &val : m_rdcr3_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_info(0, "wrcr3 log", msg);
        for(const auto &val : m_wrcr3_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_info(0, "wrcr4 log", msg);
        for(const auto &val : m_wrcr4_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_info(0, "rdcr8 log", msg);
        for(const auto &val : m_rdcr8_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_info(0, "wrcr8 log", msg);
        for(const auto &val : m_wrcr8_log) {
            bfdebug_subnhex(0, "value", val, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

#endif

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

uintptr_t
crs::emulate_rdgpr(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    using namespace ::intel_x64::vmcs::exit_qualification::control_register_access;

    switch (general_purpose_register::get())
    {
        case general_purpose_register::rax:
            return get_bits(vmcs->save_state()->rax, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rbx:
            return get_bits(vmcs->save_state()->rbx, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rcx:
            return get_bits(vmcs->save_state()->rcx, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rdx:
            return get_bits(vmcs->save_state()->rdx, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rsp:
            return get_bits(vmcs->save_state()->rsp, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rbp:
            return get_bits(vmcs->save_state()->rbp, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rsi:
            return get_bits(vmcs->save_state()->rsi, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::rdi:
            return get_bits(vmcs->save_state()->rdi, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r8:
            return get_bits(vmcs->save_state()->r08, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r9:
            return get_bits(vmcs->save_state()->r09, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r10:
            return get_bits(vmcs->save_state()->r10, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r11:
            return get_bits(vmcs->save_state()->r11, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r12:
            return get_bits(vmcs->save_state()->r12, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r13:
            return get_bits(vmcs->save_state()->r13, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r14:
            return get_bits(vmcs->save_state()->r14, 0x7FFFFFFFFFFFFFFF);

        case general_purpose_register::r15:
            return get_bits(vmcs->save_state()->r15, 0x7FFFFFFFFFFFFFFF);

        default:
            throw std::runtime_error("crs::gpr: unknown index");
    }
}

void
crs::emulate_wrgpr(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs, uintptr_t val)
{
    using namespace ::intel_x64::vmcs::exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            vmcs->save_state()->rax = val;
            return;

        case general_purpose_register::rbx:
            vmcs->save_state()->rbx = val;
            return;

        case general_purpose_register::rcx:
            vmcs->save_state()->rcx = val;
            return;

        case general_purpose_register::rdx:
            vmcs->save_state()->rdx = val;
            return;

        case general_purpose_register::rsp:
            vmcs->save_state()->rsp = val;
            return;

        case general_purpose_register::rbp:
            vmcs->save_state()->rbp = val;
            return;

        case general_purpose_register::rsi:
            vmcs->save_state()->rsi = val;
            return;

        case general_purpose_register::rdi:
            vmcs->save_state()->rdi = val;
            return;

        case general_purpose_register::r8:
            vmcs->save_state()->r08 = val;
            return;

        case general_purpose_register::r9:
            vmcs->save_state()->r09 = val;
            return;

        case general_purpose_register::r10:
            vmcs->save_state()->r10 = val;
            return;

        case general_purpose_register::r11:
            vmcs->save_state()->r11 = val;
            return;

        case general_purpose_register::r12:
            vmcs->save_state()->r12 = val;
            return;

        case general_purpose_register::r13:
            vmcs->save_state()->r13 = val;
            return;

        case general_purpose_register::r14:
            vmcs->save_state()->r14 = val;
            return;

        case general_purpose_register::r15:
            vmcs->save_state()->r15 = val;
            return;

        default:
            throw std::runtime_error("crs::set_gpr: unknown index");
    }
}

bool
crs::handle_crs(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    using namespace ::intel_x64::vmcs::exit_qualification::control_register_access;

    switch (control_register_number::get()) {
        case 0:
            return handle_wrcr0(vmcs);

        case 3:
            return handle_cr3(vmcs);

        case 4:
            return handle_wrcr4(vmcs);

        case 8:
            return handle_cr8(vmcs);

        default:
            throw std::runtime_error("crs::handle_crs: invalid cr number");
    }
}

bool
crs::handle_cr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    using namespace ::intel_x64::vmcs::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_from_cr:
            return handle_rdcr3(vmcs);

        case access_type::mov_to_cr:
            return handle_wrcr3(vmcs);

        default:
            throw std::runtime_error("crs::handle_cr3: invalid access type");
    }
}

bool
crs::handle_cr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    using namespace ::intel_x64::vmcs::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_from_cr:
            return handle_rdcr8(vmcs);

        case access_type::mov_to_cr:
            return handle_wrcr8(vmcs);

        default:
            throw std::runtime_error("crs::handle_cr8: invalid access type");
    }
}

bool
crs::handle_wrcr0(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        this->emulate_rdgpr(vmcs),
        ::intel_x64::vmcs::cr0_read_shadow::get()
    };

    for (const auto &d : m_wrcr0_handlers) {
        if (d(vmcs, info)) {
            ::intel_x64::vmcs::guest_cr0::set(info.val);
            ::intel_x64::vmcs::cr0_read_shadow::set(info.shadow);
            return advance(vmcs);
        }
    }

    return false;
}

bool
crs::handle_rdcr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        ::intel_x64::vmcs::guest_cr3::get(),
        0
    };

    for (const auto &d : m_rdcr3_handlers) {
        if (d(vmcs, info)) {
            this->emulate_wrgpr(vmcs, info.val);
            return advance(vmcs);
        }
    }

    return false;
}

bool
crs::handle_wrcr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        this->emulate_rdgpr(vmcs),
        0
    };

    for (const auto &d : m_wrcr3_handlers) {
        if (d(vmcs, info)) {
            ::intel_x64::vmcs::guest_cr3::set(info.val);
            return advance(vmcs);
        }
    }

    return false;
}

bool
crs::handle_wrcr4(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        this->emulate_rdgpr(vmcs),
        ::intel_x64::vmcs::cr4_read_shadow::get()
    };

    for (const auto &d : m_wrcr4_handlers) {
        if (d(vmcs, info)) {
            ::intel_x64::vmcs::guest_cr4::set(info.val);
            ::intel_x64::vmcs::cr4_read_shadow::set(info.shadow);
            return advance(vmcs);
        }
    }

    return false;
}

bool
crs::handle_rdcr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        0,
        0
    };

    for (const auto &d : m_rdcr8_handlers) {
        if (d(vmcs, info)) {
            this->emulate_wrgpr(vmcs, info.val);
            return advance(vmcs);
        }
    }

    return false;
}

bool
crs::handle_wrcr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    struct info_t info = {
        this->emulate_rdgpr(vmcs),
        0
    };

    for (const auto &d : m_wrcr8_handlers) {
        if (d(vmcs, info)) {
            return advance(vmcs);
        }
    }

    return false;
}

}
}
