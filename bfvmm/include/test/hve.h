//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifdef BF_INTEL_X64

#include "../hve/arch/intel_x64/apis.h"
#include "../hve/arch/intel_x64/misc/mtrrs.h"
using namespace eapis::intel_x64;

constexpr auto uc = ept::mmap::memory_type::uncacheable;
constexpr auto wb = ept::mmap::memory_type::write_back;

static inline auto
base_to_physbase(uint64_t addr)
{
    return addr >> 12;
}

static inline auto
size_to_physmask(uint64_t size)
{
    static auto addr_size = ::x64::cpuid::addr_size::phys::get();
    return ~(~((1ULL << addr_size) - 1U) | (size - 1U)) >> 12;
}

static void
enable_mtrrs(uint8_t vcnt)
{
    ::x64::msrs::ia32_mtrrcap::vcnt::set(vcnt);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(6);
    ::intel_x64::msrs::ia32_mtrr_def_type::mtrr_enable::enable();

    g_eax_cpuid[::x64::cpuid::addr_size::addr] = 43U;
}

static void
add_variable_range(uint8_t vnum, mtrrs::range_t range, bool disabled = false)
{
    using namespace ::intel_x64::msrs;

    uint64_t ia32_mtrr_physbase{};
    uint64_t ia32_mtrr_physmask{};

    if (!disabled) {
        ia32_mtrr_physmask::valid::enable(ia32_mtrr_physmask);
    }

    switch (range.type) {
        case ept::mmap::memory_type::write_back:
            ia32_mtrr_physbase::type::set(
                ia32_mtrr_physbase,
                ia32_mtrr_physbase::type::write_back
            );
            break;

        case ept::mmap::memory_type::write_protected:
            ia32_mtrr_physbase::type::set(
                ia32_mtrr_physbase,
                ia32_mtrr_physbase::type::write_protected
            );
            break;

        case ept::mmap::memory_type::write_through:
            ia32_mtrr_physbase::type::set(
                ia32_mtrr_physbase,
                ia32_mtrr_physbase::type::write_through
            );
            break;

        case ept::mmap::memory_type::write_combining:
            ia32_mtrr_physbase::type::set(
                ia32_mtrr_physbase,
                ia32_mtrr_physbase::type::write_combining
            );
            break;

        default:
            ia32_mtrr_physbase::type::set(
                ia32_mtrr_physbase,
                ia32_mtrr_physbase::type::uncacheable
            );
            break;
    };

    ia32_mtrr_physbase::physbase::set(ia32_mtrr_physbase, base_to_physbase(range.base));
    ia32_mtrr_physmask::physmask::set(ia32_mtrr_physmask, size_to_physmask(range.size));

    ::intel_x64::msrs::set(ia32_mtrr_physbase::addr + (vnum * 2), ia32_mtrr_physbase);
    ::intel_x64::msrs::set(ia32_mtrr_physmask::addr + (vnum * 2), ia32_mtrr_physmask);
}

apis *
setup_eapis(MockRepository &mocks)
{
    auto eapis = mocks.Mock<apis>();

    mocks.OnCall(eapis, apis::set_eptp);
    mocks.OnCall(eapis, apis::disable_ept);
    mocks.OnCall(eapis, apis::enable_vpid);
    mocks.OnCall(eapis, apis::disable_vpid);
    mocks.OnCall(eapis, apis::enable_wrcr0_exiting);
    mocks.OnCall(eapis, apis::enable_wrcr4_exiting);
    mocks.OnCall(eapis, apis::add_wrcr0_handler);
    mocks.OnCall(eapis, apis::add_rdcr3_handler);
    mocks.OnCall(eapis, apis::add_wrcr3_handler);
    mocks.OnCall(eapis, apis::add_wrcr4_handler);
    mocks.OnCall(eapis, apis::add_cpuid_handler);
    mocks.OnCall(eapis, apis::add_ept_misconfiguration_handler);
    mocks.OnCall(eapis, apis::add_ept_read_violation_handler);
    mocks.OnCall(eapis, apis::add_ept_write_violation_handler);
    mocks.OnCall(eapis, apis::add_ept_execute_violation_handler);
    mocks.OnCall(eapis, apis::add_external_interrupt_handler);
    mocks.OnCall(eapis, apis::add_init_signal_handler);
    mocks.OnCall(eapis, apis::add_interrupt_window_handler);
    mocks.OnCall(eapis, apis::add_io_instruction_handler);
    mocks.OnCall(eapis, apis::add_monitor_trap_handler);
    mocks.OnCall(eapis, apis::enable_monitor_trap_flag);
    mocks.OnCall(eapis, apis::add_mov_dr_handler);
    mocks.OnCall(eapis, apis::pass_through_all_rdmsr_handler_accesses);
    mocks.OnCall(eapis, apis::add_rdmsr_handler);
    mocks.OnCall(eapis, apis::add_sipi_handler);
    mocks.OnCall(eapis, apis::pass_through_all_wrmsr_handler_accesses);
    mocks.OnCall(eapis, apis::add_wrmsr_handler);
    mocks.OnCall(eapis, apis::add_handler);

    return eapis;
}

#endif
