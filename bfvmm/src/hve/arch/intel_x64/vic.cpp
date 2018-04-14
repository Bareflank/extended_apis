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

#include <arch/x64/misc.h>
#include <arch/x64/rflags.h>

#include <hve/arch/intel_x64/isr.h>
#include <hve/arch/intel_x64/vic.h>
#include <hve/arch/intel_x64/ept/memory_map.h>
#include <hve/arch/intel_x64/ept/intrinsics.h>

namespace eapis
{
namespace intel_x64
{

static auto align_1g(uintptr_t addr)
{ return (addr & ~(ept::page_size_1g - 1U)); }

static auto align_2m(uintptr_t addr)
{ return (addr & ~(ept::page_size_2m - 1U)); }

static auto align_4k(uintptr_t addr)
{ return (addr & ~(ept::page_size_4k - 1U)); }

static auto pass_through(ept::memory_map &map, uintptr_t addr)
{
    auto &entry = map.gpa_to_epte(addr);

    ept::epte::read_access::enable(entry);
    ept::epte::write_access::enable(entry);
    ept::epte::execute_access::enable(entry);
}

static auto init_xapic_ept(
    ept::memory_map &ept_mm, uintptr_t xapic_gpa, uintptr_t xapic_hpa)
{
    auto i = 0ULL;

    for (; i < align_1g(xapic_gpa); i += ept::page_size_1g) {
        ept::identity_map_1g(ept_mm, i);
        pass_through(ept_mm, i);
    }

    for (; i < align_2m(xapic_gpa); i += ept::page_size_2m) {
        ept::identity_map_2m(ept_mm, i);
        pass_through(ept_mm, i);
    }

    for (; i < align_2m(xapic_gpa) + ept::page_size_2m; i += ept::page_size_4k) {
        if (i == xapic_gpa) {
            auto &entry = ept_mm.map(xapic_gpa, xapic_hpa, ept::page_size_4k);
            ept::epte::read_access::enable(entry);
            ept::epte::write_access::disable(entry);
            ept::epte::execute_access::disable(entry);
            continue;
        }

        ept::identity_map_4k(ept_mm, i);
        pass_through(ept_mm, i);
    }

    for (; i < align_1g(xapic_gpa) + ept::page_size_1g; i += ept::page_size_2m) {
        ept::identity_map_2m(ept_mm, i);
        pass_through(ept_mm, i);
    }

    for (; i < 0x500000000ULL; i += ept::page_size_1g) {
        ept::identity_map_1g(ept_mm, i);
        pass_through(ept_mm, i);
    }

    auto &entry = ept_mm.gpa_to_epte(xapic_hpa);
    ept::epte::clear(entry);
}

vic::vic(gsl::not_null<eapis::intel_x64::hve *> hve) :
    m_hve{hve},
    m_virt_apic_base{0U}
{
    this->init_phys_idt();
    this->init_apic_base();
    this->init_phys_lapic();
    this->init_virt_lapic();
    this->init_save_state();
    this->init_interrupt_map();

    this->add_exit_handlers();
    m_phys_lapic->disable_interrupts();
}

vic::~vic()
{ ::intel_x64::cr8::set(0xFU); }

uint64_t
vic::phys_to_virt(uint64_t phys)
{ return m_interrupt_map.at(phys); }

uint64_t
vic::virt_to_phys(uint64_t virt)
{
    for (auto phys = 255U; phys >= 32U; --phys) {
        if (m_interrupt_map.at(phys) == virt) {
            return phys;
        }
    }

    return 0U;
}

void
vic::map(uint64_t phys, uint64_t virt)
{ m_interrupt_map.at(phys) = virt; }

void
vic::unmap(uint64_t virt)
{
    for (auto phys = 255U; phys >= 32U; --phys) {
        if (m_interrupt_map.at(phys) == virt) {
            m_interrupt_map.at(phys) = 0U;
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
vic::init_apic_base()
{ m_virt_apic_base = apic_base::get(); }

void
vic::init_phys_lapic()
{
    if (!::intel_x64::lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    const auto state = apic_base::state::get(m_virt_apic_base);
    switch (state) {
        case apic_base::state::x2apic:
            this->init_phys_x2apic();
            break;

        case apic_base::state::xapic:
            this->init_phys_xapic();
            break;

        case apic_base::state::disabled:
        case apic_base::state::invalid:
        default:
            throw_vic_fatal("init_phys_lapic: invalid start state: ", state);
    }
}

void
vic::init_phys_x2apic()
{ m_phys_lapic = std::make_unique<phys_x2apic>(); }

/// Note that the apic_base::get returns the *actual* physical address
/// In the absence of EPT, it is the gpa == hpa of the xAPIC.
/// Also, the xAPIC page must be mapped read-write, uncacheable (rw_uc)
void
vic::init_phys_xapic()
{
    using namespace ::bfvmm::x64;

    const auto phys = apic_base::apic_base::get(m_virt_apic_base);
    auto map = make_unique_map<uint8_t>(phys, ::x64::memory_attr::rw_uc);

    if (!map) {
        throw_vic_fatal("init_phys_xapic: failed to map phys: ", phys);
    }

    m_xapic_ump = std::move(map);
    m_phys_lapic = std::make_unique<phys_xapic>(m_xapic_ump.get());
}

void
vic::init_virt_lapic()
{
    m_virt_apic_base = ::intel_x64::msrs::ia32_apic_base::get();
    m_virt_lapic_pg = std::make_unique<uint32_t[]>(virt_lapic::s_reg_count);
    m_virt_lapic = std::make_unique<virt_lapic>(
        m_hve, m_virt_lapic_pg.get(), m_phys_lapic.get());
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
    this->add_cr8_handlers();
    this->add_lapic_handlers();
    this->add_apic_base_handlers();
    this->add_external_interrupt_handlers();
}

void
vic::add_cr8_handlers()
{
    m_hve->add_rdcr8_handler(
        control_register::handler_delegate_t::create<vic,
        &vic::handle_rdcr8>(this));

    m_hve->add_wrcr8_handler(
        control_register::handler_delegate_t::create<vic,
        &vic::handle_wrcr8>(this));
}

void
vic::add_lapic_handlers()
{
    const auto access = m_virt_lapic->access_type();

    switch (access) {
        case virt_lapic::access_t::msr:
            this->add_x2apic_handlers();
            break;

        case virt_lapic::access_t::mmio:
            this->add_xapic_handlers();
            break;

        default:
            throw_vic_fatal(
                "add_lapic_handler: unknown access type",
                static_cast<uint64_t>(access)
            );
    }
}

void
vic::add_xapic_handlers()
{
    using namespace ::intel_x64::msrs;

    const auto xapic_gpa = apic_base::apic_base::get(m_virt_apic_base);
    const auto xapic_hpa = g_mm->virtptr_to_physint(m_virt_lapic_pg.get());

    m_ept_mm = std::make_unique<ept::memory_map>();
    init_xapic_ept(*m_ept_mm, xapic_gpa, xapic_hpa);
    vmcs_n::ept_pointer::set(ept::eptp(*m_ept_mm));
    proc_ctl2::enable_ept::enable();

    m_hve->add_monitor_trap_handler(
        monitor_trap::handler_delegate_t::create<vic,
        &vic::handle_ept_write_mtf>(this));

    m_hve->add_ept_write_violation_handler(
        ept_violation::handler_delegate_t::create<vic,
        &vic::handle_ept_write>(this));
}

void
vic::add_x2apic_handlers()
{
    for (auto i = 0U; i < lapic_register::attributes.size(); ++i) {
        if (lapic_register::readable_in_x2apic(i)) {
            this->add_x2apic_read_handler(i);
        }

        if (lapic_register::writable_in_x2apic(i)) {
            this->add_x2apic_write_handler(i);
        }
    }
}

void
vic::add_x2apic_read_handler(uint64_t offset)
{
    m_hve->add_rdmsr_handler(
        lapic_register::offset_to_msr_addr(offset),
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
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_eoi_write>(this));
            break;

        case ia32_x2apic_icr::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_icr_write>(this));
            break;

        case ia32_x2apic_self_ipi::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_self_ipi_write>(this));
            break;

        default:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_write>(this));
            break;
    }
}

void
vic::add_apic_base_handlers()
{
    m_hve->add_rdmsr_handler(
        ::intel_x64::msrs::ia32_apic_base::addr,
        rdmsr::handler_delegate_t::create<vic,
        &vic::handle_rdmsr_apic_base>(this));

    m_hve->add_wrmsr_handler(
        ::intel_x64::msrs::ia32_apic_base::addr,
        wrmsr::handler_delegate_t::create<vic,
        &vic::handle_wrmsr_apic_base>(this));
}

void
vic::add_external_interrupt_handlers()
{
    const auto svr = m_virt_lapic->read_svr();
    const auto svr_vector = ::intel_x64::lapic::svr::vector::get(svr);

    for (auto vector = 32U; vector < 256U; ++vector) {
        m_hve->add_external_interrupt_handler(
            vector,
            external_interrupt::handler_delegate_t::create<vic,
            &vic::handle_external_interrupt_exit>(this));

        if (vector == svr_vector) {
            this->add_interrupt_handler(
                vector,
                handler_delegate_t::create<vic,
                &vic::handle_spurious_interrupt>(this));
        }
        else {
            this->add_interrupt_handler(
                vector,
                handler_delegate_t::create<vic,
                &vic::handle_interrupt_from_exit>(this));
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
vic::handle_ept_write_mtf(
    gsl::not_null<vmcs_t *> vmcs, monitor_trap::info_t &info)
{
    if (!m_ept_write_mtf) {
        return false;
    }

    m_ept_write_mtf = false;

    const auto apic_gpa = apic_base::apic_base::get(m_virt_apic_base);
    auto &entry = m_ept_mm->gpa_to_epte(apic_gpa);
    ept::epte::write_access::disable(entry);

    const auto val = m_virt_lapic->read_register(m_ept_write_offset);
    m_phys_lapic->write_register(m_ept_write_offset, val);

    return true;
}

bool
vic::handle_ept_write(gsl::not_null<vmcs_t *> vmcs, ept_violation::info_t &info)
{
    const auto apic_gpa = apic_base::apic_base::get(m_virt_apic_base);
    const auto exit_gpa = info.gpa;
    if (align_4k(exit_gpa) != apic_gpa) {
        return false;
    }

    const auto offset = lapic_register::mem_addr_to_offset(exit_gpa);
    if (!lapic_register::writable_in_xapic(offset)) {
        // probably should inject #GP once we're capable
        throw_vic_fatal("handle_ept_write: offset not writable: ", offset);
    }

    m_ept_write_offset = offset;
    m_ept_write_mtf = true;
    m_hve->enable_monitor_trap_flag();
    auto &entry = m_ept_mm->gpa_to_epte(apic_gpa);
    ept::epte::write_access::enable(entry);
    info.ignore_advance = true;

    return true;
}

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
    m_phys_lapic->write_tpr(info.val << 4U);

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

    this->handle_interrupt(info.vector);
    return true;
}

bool
vic::handle_spurious_interrupt(
    gsl::not_null<vmcs_t *> vmcs, external_interrupt::info_t &info)
{
    bfignored(vmcs);

    bfalert_nhex(VIC_LOG_ALERT, "Spurious interrupt handled:", info.vector);
    m_virt_lapic->inject_spurious(this->phys_to_virt(info.vector));

    return true;
}

void
vic::handle_interrupt(uint64_t phys)
{
    m_phys_lapic->write_eoi();
    m_virt_lapic->queue_injection(this->phys_to_virt(phys));
}

void
vic::add_interrupt_handler(
    uint64_t vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(std::move(d)); }

}
}
