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

static bool
emulate_ia_32e_mode_switch(
    control_register_handler::info_t &info)
{
    using namespace vmcs_n::guest_cr0;
    using namespace vmcs_n::guest_ia32_efer;
    using namespace vmcs_n::vm_entry_controls;
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

    if (unrestricted_guest::is_disabled() || lme::is_disabled()) {
        return true;
    }

    if (paging::is_enabled(info.val)) {
        lma::enable();
        ia_32e_mode_guest::enable();
        ::intel_x64::vmx::invept_global();
    }
    else {
        lma::disable();
        ia_32e_mode_guest::disable();
        ::intel_x64::vmx::invept_global();
    }

    return true;
}

static bool
default_wrcr0_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    using namespace vmcs_n::guest_cr0;
    bfignored(vmcs);

    if (paging::is_enabled() != paging::is_enabled(info.val)) {
        return emulate_ia_32e_mode_switch(info);
    }

    return true;
}

static bool
default_rdcr3_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return true;
}

static bool
default_wrcr3_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    ::intel_x64::vmx::invept_global();
    return true;
}

static bool
default_wrcr4_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    return true;
}

control_register_handler::control_register_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state
) :
    m_eapis_vcpu_global_state{eapis_vcpu_global_state}
{
    using namespace vmcs_n;

    apis->add_handler(
        exit_reason::basic_exit_reason::control_register_accesses,
        ::handler_delegate_t::create<control_register_handler, &control_register_handler::handle>(this)
    );

    this->add_wrcr0_handler(
        handler_delegate_t::create<default_wrcr0_handler>()
    );

    this->add_rdcr3_handler(
        handler_delegate_t::create<default_rdcr3_handler>()
    );

    this->add_wrcr3_handler(
        handler_delegate_t::create<default_wrcr3_handler>()
    );

    this->add_wrcr4_handler(
        handler_delegate_t::create<default_wrcr4_handler>()
    );

    this->enable_wrcr0_exiting(0);
    this->enable_wrcr4_exiting(0);
}

control_register_handler::~control_register_handler()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
control_register_handler::add_wrcr0_handler(
    const handler_delegate_t &d)
{ m_wrcr0_handlers.push_front(d); }

void
control_register_handler::add_rdcr3_handler(
    const handler_delegate_t &d)
{ m_rdcr3_handlers.push_front(d); }

void
control_register_handler::add_wrcr3_handler(
    const handler_delegate_t &d)
{ m_wrcr3_handlers.push_front(d); }

void
control_register_handler::add_wrcr4_handler(
    const handler_delegate_t &d)
{ m_wrcr4_handlers.push_front(d); }

void
control_register_handler::enable_wrcr0_exiting(
    vmcs_n::value_type mask)
{
    using namespace vmcs_n;
    mask |= m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0;

    cr0_guest_host_mask::set(mask);
    cr0_read_shadow::set(guest_cr0::get());
}

void
control_register_handler::enable_rdcr3_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::cr3_store_exiting::enable();
}

void
control_register_handler::enable_wrcr3_exiting()
{
    using namespace vmcs_n;
    primary_processor_based_vm_execution_controls::cr3_load_exiting::enable();
}

void
control_register_handler::enable_wrcr4_exiting(
    vmcs_n::value_type mask)
{
    using namespace vmcs_n;
    mask |= m_eapis_vcpu_global_state->ia32_vmx_cr4_fixed0;

    cr4_guest_host_mask::set(mask);
    cr4_read_shadow::set(guest_cr4::get());
}

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
control_register_handler::dump_log()
{
    if (!m_cr0_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "cr0 log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_cr0_log) {
                bfdebug_info(0, "record", msg);
                bfdebug_subnhex(0, "val", record.val, msg);
                bfdebug_subnhex(0, "shadow", record.shadow, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }

    if (!m_cr3_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "cr3 log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_cr3_log) {
                bfdebug_info(0, "record", msg);
                bfdebug_subnhex(0, "val", record.val, msg);
                bfdebug_subnhex(0, "shadow", record.shadow, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }

    if (!m_cr4_log.empty()) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bfdebug_lnbr(0, msg);
            bfdebug_info(0, "cr4 log", msg);
            bfdebug_brk2(0, msg);

            for (const auto &record : m_cr4_log) {
                bfdebug_info(0, "record", msg);
                bfdebug_subnhex(0, "val", record.val, msg);
                bfdebug_subnhex(0, "shadow", record.shadow, msg);
            }

            bfdebug_lnbr(0, msg);
        });
    }
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
control_register_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (control_register_number::get()) {
        case 0:
            return handle_cr0(vmcs);

        case 3:
            return handle_cr3(vmcs);

        case 4:
            return handle_cr4(vmcs);

        default:
            throw std::runtime_error(
                "control_register_handler::handle: invalid cr number"
            );
    }
}

bool
control_register_handler::handle_cr0(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr0(vmcs);

        case access_type::mov_from_cr:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: mov_from_cr not supported"
            );

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr0: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_cr3(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr3(vmcs);

        case access_type::mov_from_cr:
            return handle_rdcr3(vmcs);

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr3: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr3: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_cr4(gsl::not_null<vmcs_t *> vmcs)
{
    using namespace vmcs_n::exit_qualification::control_register_access;

    switch (access_type::get()) {
        case access_type::mov_to_cr:
            return handle_wrcr4(vmcs);

        case access_type::mov_from_cr:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: mov_from_cr not supported"
            );

        case access_type::clts:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: clts not supported"
            );

        default:
            throw std::runtime_error(
                "control_register_handler::handle_cr4: lmsw not supported"
            );
    }
}

bool
control_register_handler::handle_wrcr0(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        emulate_rdgpr(vmcs),
        vmcs_n::cr0_read_shadow::get(),
        false,
        false
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_cr0_log, {
            info.val, info.shadow
        });
    }

    info.shadow = info.val;
    info.val |= m_eapis_vcpu_global_state->ia32_vmx_cr0_fixed0;

    for (const auto &d : m_wrcr0_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    // bfdebug_transaction(0, [&](std::string * msg) {
    //     bfdebug_info(0, "handle_wrcr0", msg);
    //     bfdebug_subnhex(0, "val", info.val, msg);
    //     bfdebug_subnhex(0, "shadow", info.shadow, msg);
    // });

    if (!info.ignore_write) {
        vmcs_n::guest_cr0::set(info.val);
        vmcs_n::cr0_read_shadow::set(info.shadow);
    }

    if (!info.ignore_advance) {
        return advance(vmcs);
    }

    return true;
}

bool
control_register_handler::handle_rdcr3(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        vmcs_n::guest_cr3::get(),
        0,
        false,
        false
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_cr3_log, {
            info.val, info.shadow
        });
    }

    for (const auto &d : m_rdcr3_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        emulate_wrgpr(vmcs, info.val);
    }

    if (!info.ignore_advance) {
        return advance(vmcs);
    }

    return true;
}

bool
control_register_handler::handle_wrcr3(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        emulate_rdgpr(vmcs),
        0,
        false,
        false
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_cr3_log, {
            info.val, info.shadow
        });
    }

    for (const auto &d : m_wrcr3_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        vmcs_n::guest_cr3::set(info.val & 0x7FFFFFFFFFFFFFFF);
    }

    if (!info.ignore_advance) {
        return advance(vmcs);
    }

    return true;
}

bool
control_register_handler::handle_wrcr4(gsl::not_null<vmcs_t *> vmcs)
{
    struct info_t info = {
        emulate_rdgpr(vmcs),
        vmcs_n::cr4_read_shadow::get(),
        false,
        false
    };

    if (!ndebug && m_log_enabled) {
        add_record(m_cr4_log, {
            info.val, info.shadow
        });
    }

    info.shadow = info.val;
    info.val |= m_eapis_vcpu_global_state->ia32_vmx_cr4_fixed0;

    for (const auto &d : m_wrcr4_handlers) {
        if (d(vmcs, info)) {
            break;
        }
    }

    // bfdebug_transaction(0, [&](std::string * msg) {
    //     bfdebug_info(0, "handle_wrcr4", msg);
    //     bfdebug_subnhex(0, "val", info.val, msg);
    //     bfdebug_subnhex(0, "shadow", info.shadow, msg);
    // });

    if (!info.ignore_write) {
        vmcs_n::guest_cr4::set(info.val);
        vmcs_n::cr4_read_shadow::set(info.shadow);
    }

    if (!info.ignore_advance) {
        return advance(vmcs);
    }

    return true;
}

}
}
