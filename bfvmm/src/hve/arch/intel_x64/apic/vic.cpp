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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <bfsupport.h>
#include <bfthreadcontext.h>

#include <arch/x64/misc.h>
#include <arch/x64/rflags.h>
#include <arch/intel_x64/vmx.h>
#include <arch/intel_x64/pause.h>

#include <hve/arch/intel_x64/apic/isr.h>
#include <hve/arch/intel_x64/apic/vic.h>

/// The INIT-SIPI-SIPI sequence has to stay in sync. If the AP is not in the
/// wait-for-SIPI state, any SIPI it receives is dropped (see section 26.6.2).
///
/// The sequence begins with the BSP trapping the INIT-assert IPI. The VMM then
/// sends the IPI and waits for the AP to signal init_done from its INIT
/// exit handler. Once the init_done signal is received, the BSP intercepts
/// the first SIPI. It sends the SIPI and waits for the AP to signal sipi_done.
/// Once the BSP sees sipi_done, it re-enters and eventually traps the last
/// SIPI. It sends the SIPI and returns immediately (it doesn't wait a third
/// time).
///
/// The sequence above is performed for each AP. Note that the current
/// signalling mechanism doesn't use any locks, as Linux brings up the APs
/// sequentially. In theory, all the APs could be brought up at once; if
/// a guest tries to do this, this code will likely break.
///
/// NOTE: Only INIT *assertions* cause INIT VM-exits. INIT de-assertions
/// used on some platforms are only used to reset the local APICs' arbitration
/// IDs. On such platforms, Linux will write an assert, then a de-assert. In this
/// case, the ICR write handler absorbs the de-assertions. See sections 10.4 and
/// 10.6 for more detail.

extern bool init_done;
extern bool sipi_done;

namespace eapis
{
namespace intel_x64
{

namespace lapic = ::intel_x64::lapic;

vic::vic(gsl::not_null<eapis::intel_x64::hve *> hve)
    :
    m_interrupt_map{{0}},
m_hve{hve},
      m_virt_base_msr{apic_base::get()},
      m_x2apic_init{false}
{
    expects(lapic::is_present());
    expects(lapic::x2apic_supported());

    if (get_platform_info()->efi.enabled != 0U) {
        this->add_apic_base_handlers();
        return;
    }

    this->init_lapic();
    if (!m_x2apic_init) {
        return;
    }

    this->init_idt();
    this->init_save_state();
    this->init_interrupt_map();

    this->add_cr8_handlers();
    this->add_x2apic_handlers();
    this->add_external_interrupt_handlers();
    this->add_apic_base_handlers();
}

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

/// --------------------------------------------------------------------------
/// Initialization routines
/// --------------------------------------------------------------------------

void
vic::init_idt()
{
    const auto selector = 8U;
    set_default_isrs(m_hve->exit_handler()->host_idt(), selector);
}

void
vic::init_lapic()
{
    const auto state = apic_base::state::get();
    switch (state) {
        case apic_base::state::x2apic:
            this->init_phys_x2apic();
            break;

        case apic_base::state::xapic:
            bfalert_info(VIC_LOG_ALERT, "xAPIC state unsupported");
            bfalert_info(VIC_LOG_ALERT, "disabling APIC emulation");
            return;

        case apic_base::state::disabled:
        case apic_base::state::invalid:
        default:
            throw_vic_fatal("init_lapic: invalid start state: ", state);
    }

    this->init_virt_x2apic();
    m_x2apic_init = true;
}

void
vic::init_phys_x2apic()
{ m_phys_x2apic = std::make_unique<phys_x2apic>(); }

void
vic::init_virt_x2apic()
{ m_virt_x2apic = std::make_unique<virt_x2apic>(m_hve, m_phys_x2apic.get()); }

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
vic::add_x2apic_handlers()
{
    for (const auto addr : x2apic::registers) {
        if (x2apic::readable(addr)) {
            this->add_x2apic_read_handler(addr);
        }

        if (x2apic::writable(addr)) {
            this->add_x2apic_write_handler(addr);
        }
    }
}

void
vic::add_x2apic_read_handler(uint32_t addr)
{
    m_hve->add_rdmsr_handler(
        addr,
        rdmsr::handler_delegate_t::create<vic,
        &vic::handle_x2apic_read>(this));
}

void
vic::add_x2apic_write_handler(uint32_t addr)
{
    switch (addr) {
        case ::intel_x64::msrs::ia32_x2apic_eoi::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_eoi_write>(this));
            return;

        case ::intel_x64::msrs::ia32_x2apic_icr::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_icr_write>(this));
            return;

        case ::intel_x64::msrs::ia32_x2apic_self_ipi::addr:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_self_ipi>(this));
            return;

        default:
            m_hve->add_wrmsr_handler(
                addr,
                wrmsr::handler_delegate_t::create<vic,
                &vic::handle_x2apic_write>(this));
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
    const auto svr = m_virt_x2apic->read_svr();
    const auto svr_vector = lapic::svr::vector::get(svr);

    for (auto vector = 32U; vector < s_num_vectors; ++vector) {
        m_hve->add_external_interrupt_handler(
            vector,
            external_interrupt::handler_delegate_t::create<vic,
            &vic::handle_external_interrupt_exit>(this));

        /// We treat the spurious vector specially since the generic
        /// handle_interrupt_from_exit path writes a physical EOI
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

    // Right now this has to come after the call to add external
    // interrupt handler. The hve member should probably be checked for
    // null on external_interrupt() to fix this
    m_hve->external_interrupt()->enable_exiting();
}

/// --------------------------------------------------------------------------
/// x2apic exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_x2apic_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);
    m_virt_x2apic->write_register(info.msr, info.val);
    m_phys_x2apic->write_register(info.msr, info.val);
    info.ignore_write = true;

    return true;
}

bool
vic::handle_x2apic_eoi_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);
    m_virt_x2apic->write_eoi();
    info.ignore_write = true;

    return true;
}

static void
wait_until(const bool &done)
{
    while (true) {
        if (done) {
            return;
        }
        ::intel_x64::pause();
    }
}

bool
vic::handle_x2apic_icr_write(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    switch (lapic::icr::delivery_mode::get(info.val)) {
        case lapic::icr::delivery_mode::init: {
            /// We simply absorb INIT de-asserts. They don't cause an INIT
            /// exit, and their only purpose is to reset the target(s)
            /// arbitration IDs.
            if (lapic::icr::level::is_disabled(info.val)) {
                break;
            }

            m_virt_x2apic->write_icr(info.val);
            m_phys_x2apic->write_icr(info.val);
            wait_until(init_done);
            init_done = false;
            sipi_done = false;
            break;
        }
        case lapic::icr::delivery_mode::sipi: {
            m_virt_x2apic->write_icr(info.val);
            m_phys_x2apic->write_icr(info.val);
            wait_until(sipi_done);
            break;
        }
        default:
            m_phys_x2apic->write_icr(info.val);
            m_virt_x2apic->write_icr(info.val);
            break;
    }

    info.ignore_write = true;
    return true;
}

bool
vic::handle_x2apic_self_ipi(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);
    m_virt_x2apic->queue_injection(info.val);
    info.ignore_write = true;

    return true;
}

bool
vic::handle_x2apic_read(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);
    info.val = m_virt_x2apic->read_register(info.msr);

    return true;
}

/// --------------------------------------------------------------------------
/// Common lapic exit handlers
/// --------------------------------------------------------------------------

bool
vic::handle_rdcr8(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    info.val = m_virt_x2apic->read_tpr() >> 4U;

    return true;
}

bool
vic::handle_wrcr8(gsl::not_null<vmcs_t *> vmcs, control_register::info_t &info)
{
    bfignored(vmcs);
    m_virt_x2apic->write_tpr(info.val << 4U);
    m_phys_x2apic->write_tpr(info.val << 4U);

    return true;
}

bool
vic::handle_rdmsr_apic_base(gsl::not_null<vmcs_t *> vmcs, rdmsr::info_t &info)
{
    bfignored(vmcs);
    info.val = m_virt_base_msr;

    return true;
}

bool
vic::handle_wrmsr_apic_base(gsl::not_null<vmcs_t *> vmcs, wrmsr::info_t &info)
{
    bfignored(vmcs);

    const auto state = apic_base::state::get(info.val);
    switch (state) {
        case apic_base::state::x2apic:
            break;

        /// TODO: check if going into sleep states will cause the host vm to
        /// try switch to xapic
        case apic_base::state::xapic:
        case apic_base::state::disabled:
        case apic_base::state::invalid:
        default:
            throw_vic_fatal("wrmsr apic_base: invalid start state: ", state);
    }

    if (!m_x2apic_init) {
        apic_base::set(info.val);

        this->init_idt();
        this->init_phys_x2apic();
        this->init_virt_x2apic();
        this->init_save_state();
        this->init_interrupt_map();

        this->add_cr8_handlers();
        this->add_x2apic_handlers();
        this->add_external_interrupt_handlers();

        m_x2apic_init = true;
    }

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
    bfalert_nhex(VIC_LOG_ALERT, "Spurious interrupt handled:", info.vector);
    m_virt_x2apic->inject_spurious(this->phys_to_virt(info.vector));

    return true;
}

void
vic::handle_interrupt(uint64_t phys)
{
    m_phys_x2apic->write_eoi();
    m_virt_x2apic->queue_injection(this->phys_to_virt(phys));
}

void
vic::add_interrupt_handler(uint64_t vector, handler_delegate_t &&d)
{ m_handlers.at(vector).push_front(d); }

}
}
