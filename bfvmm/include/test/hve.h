//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifdef BF_INTEL_X64

#include "../hve/arch/intel_x64/apis.h"
#include "../hve/arch/intel_x64/mtrrs.h"
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

static inline void
enable_mtrrs(uint8_t vcnt)
{
    ::x64::msrs::ia32_mtrrcap::vcnt::set(vcnt);
    ::intel_x64::msrs::ia32_mtrr_def_type::type::set(6);
    ::intel_x64::msrs::ia32_mtrr_def_type::mtrr_enable::enable();

    g_eax_cpuid[::x64::cpuid::addr_size::addr] = 43U;
}

static inline void
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

inline apis *
setup_eapis(MockRepository &mocks)
{
    auto eapis = mocks.Mock<apis>();

    mocks.OnCall(eapis, apis::set_eptp);
    mocks.OnCall(eapis, apis::disable_ept);
    mocks.OnCall(eapis, apis::enable_vpid);
    mocks.OnCall(eapis, apis::disable_vpid);
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
    mocks.OnCall(eapis, apis::disable_external_interrupts);
    mocks.OnCall(eapis, apis::trap_on_next_interrupt_window);
    mocks.OnCall(eapis, apis::disable_interrupt_window);
    mocks.OnCall(eapis, apis::add_interrupt_window_handler);
    mocks.OnCall(eapis, apis::is_interrupt_window_open);
    mocks.OnCall(eapis, apis::inject_external_interrupt);
    mocks.OnCall(eapis, apis::add_io_instruction_handler);
    mocks.OnCall(eapis, apis::trap_all_io_instruction_accesses);
    mocks.OnCall(eapis, apis::pass_through_all_io_instruction_accesses);
    mocks.OnCall(eapis, apis::add_monitor_trap_handler);
    mocks.OnCall(eapis, apis::enable_monitor_trap_flag);
    mocks.OnCall(eapis, apis::add_mov_dr_handler);
    mocks.OnCall(eapis, apis::trap_all_rdmsr_accesses);
    mocks.OnCall(eapis, apis::pass_through_all_rdmsr_accesses);
    mocks.OnCall(eapis, apis::add_rdmsr_handler);
    mocks.OnCall(eapis, apis::trap_all_wrmsr_accesses);
    mocks.OnCall(eapis, apis::pass_through_all_wrmsr_accesses);
    mocks.OnCall(eapis, apis::add_wrmsr_handler);
    mocks.OnCall(eapis, apis::add_xsetbv_handler);
    mocks.OnCall(eapis, apis::add_handler);

    return eapis;
}

inline bfvmm::intel_x64::vmcs *
setup_vmcs(MockRepository &mocks)
{
    using namespace bfvmm::intel_x64;
    auto vmcs = mocks.Mock<bfvmm::intel_x64::vmcs>();

    mocks.OnCall(vmcs, vmcs::launch);
    mocks.OnCall(vmcs, vmcs::resume);
    mocks.OnCall(vmcs, vmcs::promote);
    mocks.OnCall(vmcs, vmcs::load);

    mocks.OnCall(vmcs, vmcs::save_state).Return(
        &g_save_state
    );

    return vmcs;
}
#endif
