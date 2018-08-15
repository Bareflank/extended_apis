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

#ifndef VIRT_X2APIC_INTEL_X64_EAPIS_H
#define VIRT_X2APIC_INTEL_X64_EAPIS_H

#include <array>
#include <unordered_map>
#include <arch/x64/misc.h>
#include <arch/intel_x64/apic/lapic.h>
#include <arch/intel_x64/apic/x2apic.h>

namespace eapis
{
namespace intel_x64
{

class hve;
class phys_x2apic;

namespace x2apic
{

const std::array<uint32_t, 44> registers = {
    ::intel_x64::msrs::ia32_x2apic_apicid::addr,
    ::intel_x64::msrs::ia32_x2apic_version::addr,
    ::intel_x64::msrs::ia32_x2apic_tpr::addr,
    ::intel_x64::msrs::ia32_x2apic_ppr::addr,
    ::intel_x64::msrs::ia32_x2apic_eoi::addr,
    ::intel_x64::msrs::ia32_x2apic_ldr::addr,
    ::intel_x64::msrs::ia32_x2apic_svr::addr,

    ::intel_x64::msrs::ia32_x2apic_isr0::addr,
    ::intel_x64::msrs::ia32_x2apic_isr1::addr,
    ::intel_x64::msrs::ia32_x2apic_isr2::addr,
    ::intel_x64::msrs::ia32_x2apic_isr3::addr,
    ::intel_x64::msrs::ia32_x2apic_isr4::addr,
    ::intel_x64::msrs::ia32_x2apic_isr5::addr,
    ::intel_x64::msrs::ia32_x2apic_isr6::addr,
    ::intel_x64::msrs::ia32_x2apic_isr7::addr,

    ::intel_x64::msrs::ia32_x2apic_tmr0::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr1::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr2::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr3::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr4::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr5::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr6::addr,
    ::intel_x64::msrs::ia32_x2apic_tmr7::addr,

    ::intel_x64::msrs::ia32_x2apic_irr0::addr,
    ::intel_x64::msrs::ia32_x2apic_irr1::addr,
    ::intel_x64::msrs::ia32_x2apic_irr2::addr,
    ::intel_x64::msrs::ia32_x2apic_irr3::addr,
    ::intel_x64::msrs::ia32_x2apic_irr4::addr,
    ::intel_x64::msrs::ia32_x2apic_irr5::addr,
    ::intel_x64::msrs::ia32_x2apic_irr6::addr,
    ::intel_x64::msrs::ia32_x2apic_irr7::addr,

    ::intel_x64::msrs::ia32_x2apic_esr::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_cmci::addr,
    ::intel_x64::msrs::ia32_x2apic_icr::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_timer::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_thermal::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_pmi::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_lint0::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_lint1::addr,
    ::intel_x64::msrs::ia32_x2apic_lvt_error::addr,

    ::intel_x64::msrs::ia32_x2apic_init_count::addr,
    ::intel_x64::msrs::ia32_x2apic_cur_count::addr,
    ::intel_x64::msrs::ia32_x2apic_dcr::addr,
    ::intel_x64::msrs::ia32_x2apic_self_ipi::addr
};

constexpr bool readable(uint32_t addr)
{
    switch (addr) {
        case ::intel_x64::msrs::ia32_x2apic_eoi::addr:
        case ::intel_x64::msrs::ia32_x2apic_self_ipi::addr:
            return false;

        default:
            return true;
    }
}

constexpr bool writable(uint32_t addr)
{
    switch (addr) {
        case ::intel_x64::msrs::ia32_x2apic_tpr::addr:
        case ::intel_x64::msrs::ia32_x2apic_eoi::addr:
        case ::intel_x64::msrs::ia32_x2apic_svr::addr:
        case ::intel_x64::msrs::ia32_x2apic_esr::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_cmci::addr:
        case ::intel_x64::msrs::ia32_x2apic_icr::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_timer::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_thermal::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_pmi::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_lint0::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_lint1::addr:
        case ::intel_x64::msrs::ia32_x2apic_lvt_error::addr:
        case ::intel_x64::msrs::ia32_x2apic_dcr::addr:
        case ::intel_x64::msrs::ia32_x2apic_self_ipi::addr:
            return true;

        default:
            return false;
    }
}
}

///
/// Virtual x2APIC
///
class EXPORT_EAPIS_HVE virt_x2apic
{
public:

    /// Constructor from physical x2APIC
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object of the virt_x2apic
    /// @param phys the phys_x2apic object for this physical core
    ///
    virt_x2apic(
        gsl::not_null<eapis::intel_x64::hve *> hve,
        eapis::intel_x64::phys_x2apic *phys
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~virt_x2apic() = default;

    /// Read Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param addr the register to read
    /// @return the value of the register
    ///
    uint64_t read_register(uint64_t addr) const;

    /// Write Register
    ///
    /// @expects
    /// @ensures
    ///
    /// @param addr the register to write
    /// @param val the value to write
    ///
    void write_register(uint64_t addr, uint64_t val);

    /// Handle interrupt window exit
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs pointer for this exit
    /// @return true iff the exit is handled
    ///
    bool handle_interrupt_window_exit(gsl::not_null<vmcs_t *> vmcs);

    /// Queue Injection
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector of the interrupt to queue
    ///
    void queue_injection(uint64_t vector);

    /// Inject spurious interrupt
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the spurious vector inject
    ///
    void inject_spurious(uint64_t vector);

    /// @cond

    ///
    /// Register reads
    ///
    uint64_t read_id() const;
    uint64_t read_version() const;
    uint64_t read_tpr() const;
    uint64_t read_svr() const;

    ///
    /// Register writes
    ///
    void write_eoi();
    void write_tpr(uint64_t tpr);
    void write_icr(uint64_t icr);
    void write_self_ipi(uint64_t vector);
    void write_svr(uint64_t svr);

    /// @endcond

#ifndef ENABLE_BUILD_TEST
private:
#endif

    /// @cond

    void queue_interrupt(uint64_t vector);
    void inject_interrupt(uint64_t vector);

    void init_registers(eapis::intel_x64::phys_x2apic *phys);
    void init_interrupt_window_handler();

    bool irr_is_empty();
    bool isr_is_empty();
    bool is_empty_256bit(uint64_t last);

    void pop_irr();
    void pop_isr();
    void pop_256bit(uint64_t last);

    uint64_t top_irr();
    uint64_t top_isr();
    uint64_t top_256bit(uint64_t last);

    eapis::intel_x64::hve *m_hve;
    std::unordered_map<uint64_t, uint64_t> m_reg;

    /// @endcond

public:

    /// @cond

    virt_x2apic(virt_x2apic &&) = default;
    virt_x2apic &operator=(virt_x2apic &&) = default;

    virt_x2apic(const virt_x2apic &) = delete;
    virt_x2apic &operator=(const virt_x2apic &) = delete;

    /// @endcond
};


}
}

#endif
