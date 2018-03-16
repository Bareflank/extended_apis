//
// Bareflank Hypervisor
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

#include <bfthreadcontext.h>

#include <vic/arch/intel_x64/isr.h>
#include <vic/arch/intel_x64/vic.h>

namespace eapis
{
namespace intel_x64
{

vic::vic(
    gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_hve{hve},
    m_virt_apic_base{0}
{
    init_phys_idt();
    init_phys_lapic();
    init_virt_lapic();
    init_save_state();
    init_interrupt_map();

    add_exit_handlers();
    m_phys_lapic->disable_interrupts();
}

vic::~vic()
{
    ::intel_x64::cr8::set(0xFU);
}

uint64_t
vic::phys_to_virt(uint64_t piv)
{ return m_interrupt_map.at(piv); }

uint64_t
vic::virt_to_phys(uint64_t viv)
{
    for (auto v = 256U; v >= 32U; --v) {
        if (m_interrupt_map.at(v) == viv) {
            return v;
        }
    }

    return 0U;
}

void
vic::map(uint64_t viv, uint64_t piv)
{ m_interrupt_map.at(piv) = viv; }

void
vic::unmap(uint64_t viv)
{
    for (auto v = 256U; v >= 32U; --v) {
        if (m_interrupt_map.at(v) == viv) {
            m_interrupt_map.at(v) = 0U;
        }
    }
}

void
vic::send_phys_ipi(uint64_t icr)
{ m_phys_lapic->write_icr(icr); }

void
vic::send_virt_ipi(uint64_t icr)
{ m_virt_lapic->queue_injection(icr); }

/// --------------------------------------------------------------------------
/// Initialization routines
/// --------------------------------------------------------------------------

void
vic::init_phys_idt()
{
    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE << 1U);
    m_hve->exit_handler()->host_tss()->ist1 = setup_stack(m_ist1.get());

    const auto selector = 0x8U;
    set_default_isrs(m_hve->exit_handler()->host_idt(), selector);
}

void
vic::init_phys_lapic()
{
    if (!::intel_x64::lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    if (::intel_x64::lapic::x2apic_supported()) {
        init_phys_x2apic();
        return;
    }

    throw std::runtime_error("x2apic not supported");
}

void
vic::init_phys_x2apic()
{
    const auto state = ::intel_x64::msrs::ia32_apic_base::state::get();

    switch (state) {
        case ::intel_x64::msrs::ia32_apic_base::state::x2apic:
            break;

        case ::intel_x64::msrs::ia32_apic_base::state::disabled:
        case ::intel_x64::msrs::ia32_apic_base::state::invalid:
        case ::intel_x64::msrs::ia32_apic_base::state::xapic:
        default:
            bferror_info(VIC_LOG_ERROR, "init_phys_x2apic: unsupported start state");
            bferror_nhex(VIC_LOG_ERROR, "state", state);

            throw std::runtime_error(
                "init_phys_x2apic: unsupported start state" +
                std::to_string(state)
            );
    }

    m_phys_lapic = std::make_unique<phys_x2apic>();
}

void
vic::init_virt_lapic()
{
    using namespace ::intel_x64::msrs;

    m_virt_apic_base = ia32_apic_base::get();
    m_virt_apic_base = ia32_apic_base::state::enable_x2apic(m_virt_apic_base);

    m_virt_lapic = std::make_unique<virt_x2apic>(m_hve, m_phys_lapic.get());
}

void
vic::init_save_state()
{
    auto state = m_hve->vmcs()->save_state();
    state->vic_ptr = reinterpret_cast<uintptr_t>(this);
}

void
vic::init_interrupt_map()
{
    for (auto i = 0U; i < m_interrupt_map.size(); ++i) {
        this->map(i, i);
    }
}

/// --------------------------------------------------------------------------
/// Exit handler registration
/// --------------------------------------------------------------------------

void
vic::add_exit_handlers()
{
    add_cr8_handlers();
    add_x2apic_handlers();
    add_apic_base_handlers();
    add_external_interrupt_handlers();
}

void
vic::add_cr8_handlers()
{
    m_hve->add_rdcr8_handler(
        control_register::handler_delegate_t::create<
        vic, &vic::handle_rdcr8>(this)
    );

    m_hve->add_wrcr8_handler(
        control_register::handler_delegate_t::create<
        vic, &vic::handle_wrcr8>(this)
    );
}

void
vic::add_x2apic_handlers()
{
    for (auto i = 0U; i < lapic_register::attributes.size(); ++i) {
        if (lapic_register::readable_in_x2apic(i)) {
            add_x2apic_read_handler(i);
        }

        if (lapic_register::writable_in_x2apic(i)) {
            add_x2apic_write_handler(i);
        }
    }
}

void
vic::add_x2apic_read_handler(uint64_t offset)
{
    m_hve->add_rdmsr_handler(lapic_register::offset_to_msr_addr(offset),
        rdmsr::handler_delegate_t::create<vic,
        &vic::handle_x2apic_read>(this)
    );
}

void
vic::add_x2apic_write_handler(uint64_t offset)
{
    using namespace ::intel_x64::msrs;

    const auto addr = lapic_register::offset_to_msr_addr(offset);
    switch (addr) {
        case ia32_x2apic_eoi::addr:
            m_hve->add_wrmsr_handler(addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_eoi_write>(this)
            );
            break;

        case ia32_x2apic_icr::addr:
            m_hve->add_wrmsr_handler(addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_icr_write>(this)
            );
            break;

        case ia32_x2apic_self_ipi::addr:
            m_hve->add_wrmsr_handler(addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_self_ipi_write>(this)
            );
            break;

        default:
            m_hve->add_wrmsr_handler(addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_write>(this)
            );
            break;
    }
}

void
vic::add_apic_base_handlers()
{
    m_hve->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_apic_base::addr,
        rdmsr::handler_delegate_t::create<vic,
        &vic::handle_rdmsr_apic_base>(this)
    );

    m_hve->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_apic_base::addr,
        wrmsr::handler_delegate_t::create<vic,
        &vic::handle_wrmsr_apic_base>(this)
    );
}

void
vic::add_external_interrupt_handlers()
{
    if (!m_virt_lapic) {
        bferror_info(VIC_LOG_ERROR, "vic: Uninitialized virt_lapic");
        bferror_subtext(VIC_LOG_ERROR, "NULL in", "add_external_interrupt_handler");
        throw std::runtime_error("Initialize virt_lapic before adding "
            + "external interrupt handlers"_s);
    }

    const auto svr = m_virt_lapic->read_svr();
    const auto svr_vector = ::intel_x64::lapic::svr::vector::get(svr);

    for (auto vector = 32U; vector < 256U; ++vector) {
        m_hve->add_external_interrupt_handler(vector,
            external_interrupt::handler_delegate_t::create<vic,
            &vic::handle_external_interrupt_exit>(this)
        );

        if (vector == svr_vector) {
            add_interrupt_handler(vector,
                handler_delegate_t::create<vic,
                &vic::handle_spurious_interrupt>(this)
            );
        } else {
            add_interrupt_handler(vector,
                handler_delegate_t::create<vic,
                &vic::handle_interrupt_from_exit>(this)
            );
        }
    }

    // NOTE: right now this has to come after the call to add external
    // interrupt handler. The hve member should probably be checked for
    // null on external_interrupt() to fix this
    m_hve->external_interrupt()->enable_exiting();
}

/// --------------------------------------------------------------------------
/// Exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_x2apic_write(
    gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic_register::msr_addr_to_offset(info.msr);

    m_virt_lapic->write_register(offset, info.val);
    m_phys_lapic->write_register(offset, info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_eoi_write(
    gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_icr_write(
    gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    m_virt_lapic->write_icr(info.val);
    m_phys_lapic->write_icr(info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_self_ipi_write(
    gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    m_virt_lapic->write_self_ipi(info.val);
    m_phys_lapic->write_self_ipi(info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_read(
    gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic_register::msr_addr_to_offset(info.msr);
    info.val = m_virt_lapic->read_register(offset);

    info.ignore_write = false;
    info.ignore_advance = false;

    return true;
}


bool
vic::handle_rdcr8(
    gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);

    info.val = m_virt_lapic->read_tpr() >> 4U;

    info.ignore_write = false;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_wrcr8(
    gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);

    m_virt_lapic->write_tpr(info.val << 4U);

    info.ignore_write = false;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_rdmsr_apic_base(
    gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);

    bfdebug_info(VIC_LOG_ALERT, "rdmsr: apic_base");
    info.val = m_virt_apic_base;

    return true;
}

// TODO complete implementation w/ mode switching
// once ept is available
bool
vic::handle_wrmsr_apic_base(
    gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    bfdebug_info(VIC_LOG_ALERT, "wrmsr: apic_base");
    m_virt_apic_base = info.val;

    return true;
}

bool
vic::handle_external_interrupt_exit(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info)
{
    for (const auto &d : m_handlers.at(info.vector)) {
        if (d(vmcs, info)) {
            return true;
        }
    }

    return false;
}

bool
vic::handle_interrupt_from_exit(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info)
{
    bfignored(vmcs);

    handle_interrupt(info.vector);
    return true;
}

bool
vic::handle_spurious_interrupt(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info)
{
    bfignored(vmcs);

    bfdebug_nhex(0, "Spurious interrupt handled", info.vector);
    m_virt_lapic->queue_injection(info.vector);

    return true;
}

void
vic::handle_interrupt(uint64_t piv)
{
    m_phys_lapic->write_eoi();
    m_virt_lapic->queue_injection(phys_to_virt(piv));
}

void
vic::add_interrupt_handler(
    uint64_t vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(std::move(d)); }

}
}
