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

#include <bfcapstone.h>
#include <bfsupport.h>
#include <bfthreadcontext.h>

#include <arch/x64/misc.h>
#include <arch/x64/rflags.h>
#include <arch/intel_x64/vmx.h>

#include <hve/arch/intel_x64/esr.h>
#include <hve/arch/intel_x64/isr.h>
#include <hve/arch/intel_x64/vic.h>
#include <hve/arch/intel_x64/ept/helpers.h>
#include <hve/arch/intel_x64/ept/intrinsics.h>
#include <hve/arch/intel_x64/ept/memory_map.h>

namespace eapis
{
namespace intel_x64
{

namespace lapic = ::intel_x64::lapic;

vic::vic(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    gsl::not_null<eapis::intel_x64::ept::memory_map *> emm
) :
    m_virt_base_msr{apic_base::get()},
    m_orig_base_msr{apic_base::get()},
    m_hve{hve},
    m_emm{emm}
{
    this->init_idt();
    this->init_save_state();
    this->init_interrupt_map();

    if (!get_platform_info()->efi.enabled) {
        this->init_lapic();
        this->add_exit_handlers();
        m_phys_lapic->relocate(reinterpret_cast<uintptr_t>(m_xapic_ump.get()));
        return;
    }

    this->add_apic_base_handlers();
    ept::identity_map(*m_emm, 0, 0x900000000 - 0x1000);
    ept::enable_ept(ept::eptp(*m_emm), m_hve);
}

vic::~vic()
{ ::intel_x64::cr8::set(0xFULL); }

uint64_t
vic::phys_to_virt(uint64_t phys)
{ return m_interrupt_map.at(phys); }

uint64_t
vic::virt_to_phys(uint64_t virt)
{
    for (auto phys = 255ULL; phys >= 32ULL; --phys) {
        if (m_interrupt_map.at(phys) == virt) {
            return phys;
        }
    }

    return 0ULL;
}

void
vic::map(uint64_t phys, uint64_t virt)
{ m_interrupt_map.at(phys) = gsl::narrow_cast<uint8_t>(virt); }

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

// TODO: remove me
void
vic::send_virt_ipi(uint64_t icr)
{ m_virt_lapic->queue_injection(icr); }

/// --------------------------------------------------------------------------
/// Initialization routines
/// --------------------------------------------------------------------------

void
vic::init_idt()
{
    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE << 1U);
    m_hve->exit_handler()->host_tss()->ist1 = setup_stack(m_ist1.get());

    const auto selector = 8U;
    set_default_esrs(m_hve->exit_handler()->host_idt(), selector);
    set_default_isrs(m_hve->exit_handler()->host_idt(), selector);
}

void
vic::init_lapic()
{
    if (!lapic::is_present()) {
        throw std::runtime_error("lapic not present");
    }

    const auto state = apic_base::state::get(m_orig_base_msr);
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
            throw_vic_fatal("init_lapic: invalid start state: ", state);
    }

    this->init_virt_lapic();
}


void
vic::init_phys_x2apic()
{ m_phys_lapic = std::make_unique<phys_x2apic>(); }

/// Note that the apic_base::get returns the *actual* physical address
/// and that this 4K page must be mapped in read-write, uncacheable (rw_uc)
void
vic::init_phys_xapic()
{
    using namespace bfvmm::x64;

    const auto orig_virt = get_platform_info()->xapic_virt;
    const auto orig_phys = apic_base::apic_base::get(m_orig_base_msr);
    auto map = make_unique_map<uint8_t>(orig_phys, x64::memory_attr::rw_uc);

    if (map == nullptr) {
        throw_vic_fatal("init_phys_xapic: unable to map in xAPIC page");
    }

    if (orig_virt == 0ULL) {
        throw_vic_fatal("init_phys_xapic: NULL platform_info_t::xapic_virt");
    }

    m_xapic_ump = std::move(map);
    m_phys_lapic = std::make_unique<phys_xapic>(orig_virt);
}

void
vic::init_virt_lapic()
{ m_virt_lapic = std::make_unique<virt_lapic>(m_hve, m_phys_lapic.get()); }

void
vic::init_save_state()
{
    auto state = m_hve->vmcs()->save_state();
    state->vic_ptr = reinterpret_cast<uintptr_t>(this);
}

void
vic::init_interrupt_map()
{
    for (auto i = 0ULL; i < s_num_vectors; ++i) {
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
        case virt_lapic::access_t::msrs:
            this->add_x2apic_handlers();
            break;

        case virt_lapic::access_t::mmio:
            this->add_xapic_handlers();
            break;

        default:
            throw_vic_fatal(
                "add_lapic_handler: unknown access type",
                static_cast<uint64_t>(access));
    }
}

void
vic::add_xapic_handlers()
{
    using namespace ::intel_x64::msrs;

    expects(m_virt_base_msr == m_orig_base_msr);
    expects(m_emm != nullptr);

    const auto xapic_gpa = apic_base::apic_base::get(m_virt_base_msr);
    const auto shadow_hpa = g_mm->virtint_to_physint(m_virt_lapic->base());

    ept::identity_map(*m_emm, 0, xapic_gpa - 0x1000);
    ept::map_4k(*m_emm, xapic_gpa, shadow_hpa, ept::epte::memory_attr::uc_re);
    ept::identity_map(*m_emm, xapic_gpa + 0x1000, 0x900000000 - 0x1000);

//    m_hve->add_ept_read_violation_handler(
//        ept_violation::handler_delegate_t::create<vic,
//        &vic::handle_xapic_read>(this));

//    m_hve->add_ept_write_violation_handler(
//        ept_violation::handler_delegate_t::create<vic,
//        &vic::handle_xapic_write>(this));
//
//    ept::enable_ept(ept::eptp(*m_emm), m_hve);
}

void
vic::add_x2apic_handlers()
{
    for (const auto i : lapic::offset::list) {
        if (lapic::readable_in_x2apic(i)) {
            this->add_x2apic_read_handler(i);
        }

        if (lapic::writable_in_x2apic(i)) {
            this->add_x2apic_write_handler(i);
        }
    }
}

void
vic::add_x2apic_read_handler(uint64_t offset)
{
    using namespace ::intel_x64::msrs;

    const auto addr = lapic::offset::to_msr_addr(offset);
    switch (addr) {
        case ia32_x2apic_icr::addr:
            m_hve->add_rdmsr_handler(
                addr,
                rdmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_icr_read>(this));
            break;

        default:
            m_hve->add_rdmsr_handler(
                addr,
                rdmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_read>(this));
            break;
    }
}

void
vic::add_x2apic_write_handler(uint64_t offset)
{
    using namespace ::intel_x64::msrs;

    const auto addr = lapic::offset::to_msr_addr(offset);
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
                &vic::handle_x2apic_self_ipi>(this));
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
    const auto svr_vector = lapic::svr::vector::get(svr);

    for (auto vector = 32U; vector < s_num_vectors; ++vector) {
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
/// xapic exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_xapic_read(gsl::not_null<vmcs_t *> vmcs, ept_violation::info_t &info)
{
    using namespace ::bfvmm::x64;
    using namespace ::intel_x64::msrs;

    const auto rip = vmcs_n::guest_rip::get();
    auto pair = m_read_cache.find(rip);
    if (pair == m_read_cache.end()) {
        const auto off = rip & (ept::page_size_4k - 1U);
        const auto size = (off > 0xFF0U) ? 2U * ept::page_size_4k : ept::page_size_4k;
        const auto pat = vmcs_n::guest_ia32_pat::get();
        const auto cr3 = vmcs_n::guest_cr3::get();

        auto ump = make_unique_map<uint8_t>(rip, ept::align_4k(cr3), size, pat);
        if (GSL_UNLIKELY(ump == nullptr)) {
            throw_vic_fatal("handle_xapic_read: unable to map guest_rip", rip);
        }

        m_read_cache[rip] = std::move(ump);
        pair = m_read_cache.find(rip);
    }

    uint32_t *dst = get_dst_addr(vmcs, pair->second.get());
    const auto reg = lapic::offset::from_mem_addr(info.gpa);
    *dst = gsl::narrow_cast<uint32_t>(m_virt_lapic->read_register(reg));

    return true;
}

bool
vic::handle_xapic_write(gsl::not_null<vmcs_t *> vmcs, ept_violation::info_t &info)
{
    using namespace ::bfvmm::x64;
    using namespace ::intel_x64::msrs;

    const auto reg = lapic::offset::from_mem_addr(info.gpa);
    if (reg == lapic::offset::eoi) {
        // Returning straight-away here without checking the value assumes that
        // the guest wrote a zero; if not then we technically should inject a GP
        m_virt_lapic->write_eoi();
        return true;
    }

    const auto rip = vmcs_n::guest_rip::get();
    auto pair = m_write_cache.find(rip);
    if (pair == m_write_cache.end()) {
        const auto off = rip & (ept::page_size_4k - 1U);

        // We need two pages if the instruction straddles a page boundary.
        const auto size = (off > 0xFF0U) ? 2U * ept::page_size_4k : ept::page_size_4k;
        const auto pat = vmcs_n::guest_ia32_pat::get();
        const auto cr3 = vmcs_n::guest_cr3::get();
        auto ump = make_unique_map<uint8_t>(rip, ept::align_4k(cr3), size, pat);
        if (GSL_UNLIKELY(ump == nullptr)) {
            throw_vic_fatal("handle_xapic_write: unable to map guest_rip", rip);
        }

        m_write_cache[rip] = std::move(ump);
        pair = m_write_cache.find(rip);
    }

    uint64_t val = parse_written_val(vmcs, pair->second.get());
    if (reg == lapic::offset::icr0) {
        val |= (m_virt_lapic->read_register(lapic::offset::icr1) << 32U);
        val &= ~0x1000ULL; // ensure guest sees IPI as sent
        //return this->handle_ipi(val);
    //    if (xapic_debug) {
    //        lapic::icr::dump(0, val);
    //    }
    }// else if (xapic_debug) {
    //    bfdebug_nhex(0, "xa write", reg);
    //    bfdebug_subnhex(0, "val", val);
    //}

    m_virt_lapic->write_register(reg, val);
    m_phys_lapic->write_register(reg, val);

    return true;
}

/// We have to check how the guest programmed the ICR before
/// calling queue_injection; a necessary condition for
/// injecting the vector through VM entry is that the delivery
/// mode is *fixed*. So INITs and SIPIs can't be injected, and we
/// have to ensure that we only write to the physical lapic
/// in those two cases.
bool
vic::handle_ipi(uint64_t icr)
{
    using namespace lapic::icr;

    const uint64_t deliv = delivery_mode::get(icr);
    switch (deliv) {
        case delivery_mode::fixed:
            break;

        case delivery_mode::lowest_priority:
        case delivery_mode::smi:
        case delivery_mode::nmi:
        case delivery_mode::init:
        case delivery_mode::sipi:
            m_virt_lapic->write_icr(icr);
            m_phys_lapic->write_icr(icr);
            return true;
    }

    uint64_t shorthand = destination_shorthand::get(icr);
    switch (shorthand) {
        case destination_shorthand::none:
            break;

        case destination_shorthand::self:
            m_virt_lapic->queue_injection(vector::get(icr));
            m_virt_lapic->write_icr(icr);
            return true;

        case destination_shorthand::all_incl_self:
            m_virt_lapic->queue_injection(vector::get(icr));
            destination_shorthand::set(
                icr, destination_shorthand::all_excl_self);
            m_virt_lapic->write_icr(icr);
            m_phys_lapic->write_icr(icr);
            return true;

        case destination_shorthand::all_excl_self:
            m_virt_lapic->write_icr(icr);
            m_phys_lapic->write_icr(icr);
            return true;

        default:
            bferror_nhex(
                0, "Received IPI with unknown destination_shorthand:", shorthand);
            return true;
    }

    // TODO: "self" could still be specified by the destination_mode and/or
    // destination field. If "self" is a destination, we really should
    // queue the vector here to save a world switch (this is the reason
    // for the separate case from all_excl_self)
    m_virt_lapic->write_icr(icr);
    m_phys_lapic->write_icr(icr);
    return true;
}

/// --------------------------------------------------------------------------
/// x2apic exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_x2apic_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic::offset::from_msr_addr(info.msr);

    m_virt_lapic->write_register(offset, info.val);
    m_phys_lapic->write_register(offset, info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_eoi_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    m_virt_lapic->write_eoi();

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_icr_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    const auto mode = lapic::icr::delivery_mode::get(info.val);
    switch (mode) {
        case lapic::icr::delivery_mode::init:
        case lapic::icr::delivery_mode::sipi:
            lapic::icr::dump(0, info.val);
            break;
        default:
            break;
    }

    m_virt_lapic->write_icr(info.val);
    m_phys_lapic->write_icr(info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_self_ipi(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    m_virt_lapic->queue_injection(info.val);

    info.ignore_write = true;
    info.ignore_advance = false;

    return true;
}

bool
vic::handle_x2apic_icr_read(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);
    info.val = m_virt_lapic->read_icr();
    return true;
}

bool
vic::handle_x2apic_read(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic::offset::from_msr_addr(info.msr);
    info.val = m_virt_lapic->read_register(offset);

    return true;
}

/// --------------------------------------------------------------------------
/// Common lapic exit handlers
/// --------------------------------------------------------------------------

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
vic::handle_rdmsr_apic_base(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);

    info.val = m_virt_base_msr;
    return true;
}

// TODO complete implementation w/ mode switching
// once ept is available
bool
vic::handle_wrmsr_apic_base(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);
    bfdebug_nhex(0, "wrmsr apic_base", info.val);

    const auto state = apic_base::state::get(info.val);
    switch (state) {
        case apic_base::state::x2apic:
            apic_base::set(info.val);
            this->init_phys_x2apic();
            break;

        case apic_base::state::xapic:
        case apic_base::state::disabled:
        case apic_base::state::invalid:
        default:
            throw_vic_fatal("init_lapic: invalid start state: ", state);
    }

    this->init_virt_lapic();
    this->add_cr8_handlers();
    this->add_lapic_handlers();
    this->add_external_interrupt_handlers();

    m_virt_base_msr = info.val;
    info.ignore_write = true;
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

    bfalert_nhex(0, "Spurious interrupt handled:", info.vector);
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
vic::add_interrupt_handler(uint64_t vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(std::move(d)); }

}
}
