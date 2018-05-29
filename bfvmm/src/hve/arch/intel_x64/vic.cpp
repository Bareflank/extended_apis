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

/// Initialize the ept permissions to virtualize xAPIC accesses
///
/// The xAPIC is mapped to a 4KB page with guest-physical address equal
/// to apic_base::apic_base::get(m_virt_base_msr). We map that gpa to
/// a shadow page (m_virt_lapic_regs) and trap on write accesses. Since
/// the virtual lapic page has already been initialized to the values we want,
/// we can pass through reads to the shadow page, but we still need to trap
/// on writes.
///
static auto init_xapic_ept(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    ept::memory_map &emm,
    uintptr_t xapic_gpa,
    uintptr_t xapic_hpa)
{
    expects(ept::align_4k(xapic_gpa) > 0ULL);

    const auto lo_end = ept::align_4k(xapic_gpa) - ept::page_size_4k;
    const auto hi_end = 0x900000000ULL - ept::page_size_1g;

    ept::identity_map_bestfit_lo(emm, 0ULL, lo_end);
    ept::map_4k(emm, xapic_gpa, xapic_hpa, ept::epte::memory_attr::uc_re);
    ept::identity_map_bestfit_hi(emm, xapic_gpa + ept::page_size_4k, hi_end);
    ept::enable_ept(ept::eptp(emm), hve);
}

vic::vic(
    gsl::not_null<eapis::intel_x64::hve *> hve,
    gsl::not_null<eapis::intel_x64::ept::memory_map *> emm
) :
    m_virt_base_msr{0ULL},
    m_phys_base_msr{0ULL},
    m_orig_base_msr{apic_base::get()},
    m_hve{hve},
    m_emm{emm}
{
    this->init_idt();
    this->init_lapic();
    this->init_save_state();
    this->init_interrupt_map();

    this->add_exit_handlers();

    m_phys_lapic->disable_interrupts();
    m_phys_lapic->relocate(reinterpret_cast<uintptr_t>(m_xapic_ump.get()));
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
{
    static_assert(lapic::count > 0ULL, "Need lapic_register::count > 0");

    m_virt_base_msr = m_orig_base_msr;
    m_virt_lapic = std::make_unique<virt_lapic>(
                       m_hve, m_virt_lapic_regs.data(), m_phys_lapic.get()
                   );
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
    const auto shadow_hpa = g_mm->virtptr_to_physint(m_virt_lapic_regs.data());

    init_xapic_ept(m_hve, *m_emm, xapic_gpa, shadow_hpa);

    m_hve->add_ept_write_violation_handler(
        ept_violation::handler_delegate_t::create<vic,
        &vic::handle_xapic_write>(this));
}

void
vic::add_x2apic_handlers()
{
    for (auto i = 0U; i < lapic::attributes.size(); ++i) {
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
    m_hve->add_rdmsr_handler(
        lapic::offset_to_msr_addr(offset),
        rdmsr::handler_delegate_t::create<vic,
        &vic::handle_x2apic_read>(this)
    );
}

void
vic::add_x2apic_write_handler(uint64_t offset)
{
    using namespace ::intel_x64::msrs;

    const auto addr = lapic::offset_to_msr_addr(offset);
    switch (addr) {
        case ia32_x2apic_eoi::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_eoi_write>(this));
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
    auto svr = m_virt_lapic->read_svr();
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
vic::handle_xapic_write(gsl::not_null<vmcs_t *> vmcs, ept_violation::info_t &info)
{
    using namespace ::bfvmm::x64;
    using namespace ::intel_x64::msrs;

    const auto exit_base = ept::align_4k(info.gpa);
    const auto virt_base = ia32_apic_base::apic_base::get(m_virt_base_msr);
    if (exit_base != virt_base) {
        return false;
    }

    const auto reg = lapic::mem_addr_to_offset(info.gpa);
    if (reg == lapic::msr_addr_to_offset(ia32_x2apic_eoi::addr)) {
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
        if (ump == nullptr) {
            throw_vic_fatal("handle_xapic_write: unable to map guest_rip", rip);
        }

        m_write_cache[rip] = std::move(ump);
        pair = m_write_cache.find(rip);
    }

    const auto val = parse_written_val(vmcs, pair->second.get());

    m_virt_lapic->write_register(reg, val);
    m_phys_lapic->write_register(reg, val);

    return true;
}

/// --------------------------------------------------------------------------
/// x2apic exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_x2apic_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic::msr_addr_to_offset(info.msr);

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
vic::handle_x2apic_read(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);

    const auto offset = lapic::msr_addr_to_offset(info.msr);
    info.val = m_virt_lapic->read_register(offset);

    info.ignore_write = false;
    info.ignore_advance = false;

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

    bfdebug_info(VIC_LOG_ALERT, "rdmsr: apic_base");
    info.val = m_virt_base_msr;

    return true;
}

// TODO complete implementation w/ mode switching
// once ept is available
bool
vic::handle_wrmsr_apic_base(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    bfdebug_info(VIC_LOG_ALERT, "wrmsr: apic_base");
    m_virt_base_msr = info.val;

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
vic::add_interrupt_handler(uint64_t vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(std::move(d)); }

}
}
