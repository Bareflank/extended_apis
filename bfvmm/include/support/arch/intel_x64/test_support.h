
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

#ifndef TEST_SUPPORT_EAPIS_H
#define TEST_SUPPORT_EAPIS_H

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bfsupport.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <bfvmm/test/support.h>

#include "../../../hve/arch/intel_x64/hve.h"
#include "../../../hve/arch/intel_x64/apic/vic.h"
#include "../../../hve/arch/intel_x64/ept/memory_map.h"

namespace msrs_n = ::intel_x64::msrs;
namespace lapic_n = ::intel_x64::lapic;
namespace cpuid_n = ::intel_x64::cpuid;
namespace pin_ctls = vmcs_n::pin_based_vm_execution_controls;
namespace exit_ctls = vmcs_n::vm_exit_controls;

::intel_x64::vmcs::value_type g_vcpuid{0U};

std::unique_ptr<uint32_t[]> g_vmcs_region;
std::unique_ptr<eapis::intel_x64::ept::memory_map> g_emap;

struct platform_info_t g_platform_info;

extern "C" void
_pause(void) noexcept
{ }

extern "C" uint64_t
_bsr(uint64_t value) noexcept
{
    for (size_t i = 63U; i >= 0U; --i) {
        if (((1ULL << i) & value) != 0U) {
            return i;
        }
    }
    return ~0ULL;
}

extern "C" uint64_t
_bsf(uint64_t value) noexcept
{
    for (size_t i = 0U; i < 64U; ++i) {
        if (((1ULL << i) & value) != 0U) {
            return i;
        }
    }
    return ~0ULL;
}

extern "C" uint64_t
_popcnt(uint64_t value) noexcept
{
    size_t count = 0U;
    for (size_t i = 0U; i < 64U; ++i) {
        if (((1ULL << i) & value) != 0U) {
            ++count;
        }
    }
    return count;
}

extern "C" struct platform_info_t *
get_platform_info(void)
{ return &g_platform_info; }

extern "C" void _sfence()
{ return; }

inline auto
setup_hve()
{
    bfignored(g_mm);
    setup_test_support();

    static auto g_vmcs = std::make_unique<bfvmm::intel_x64::vmcs>(g_vcpuid);
    static auto g_ehlr = std::make_unique<bfvmm::intel_x64::exit_handler>(g_vmcs.get());

    return std::make_unique<eapis::intel_x64::hve>(g_ehlr.get(), g_vmcs.get());
}

inline auto
setup_ept()
{
    if (g_emap == nullptr) {
        g_emap = std::make_unique<eapis::intel_x64::ept::memory_map>();
    }

    return g_emap.get();
}

inline auto
disable_lapic()
{
    namespace info = cpuid_n::feature_information;

    uint32_t val = g_edx_cpuid[info::addr];
    val = gsl::narrow_cast<uint32_t>(clear_bit(val, info::edx::apic::from));
    g_edx_cpuid[info::addr] = val;
}

inline auto
enable_lapic()
{
    namespace info = cpuid_n::feature_information;

    uint32_t val = g_edx_cpuid[info::addr];
    val = gsl::narrow_cast<uint32_t>(set_bit(val, info::edx::apic::from));
    g_edx_cpuid[info::addr] = val;
}


inline auto
disable_x2apic()
{
    namespace info = cpuid_n::feature_information;

    uint32_t val = g_ecx_cpuid[info::addr];
    val = gsl::narrow_cast<uint32_t>(clear_bit(val, info::ecx::x2apic::from));
    g_ecx_cpuid[info::addr] = val;
}

inline auto
enable_x2apic()
{
    namespace info = cpuid_n::feature_information;

    uint32_t val = g_ecx_cpuid[info::addr];
    val = gsl::narrow_cast<uint32_t>(set_bit(val, info::ecx::x2apic::from));
    g_ecx_cpuid[info::addr] = val;
}

inline auto
setup_x2apic()
{
    enable_lapic();
    enable_x2apic();
    msrs_n::ia32_apic_base::state::enable_x2apic();
}

inline auto
setup_vic(gsl::not_null<eapis::intel_x64::hve *> hve)
{
    setup_x2apic();
    return eapis::intel_x64::vic(hve);
}

inline auto
open_interrupt_window()
{
    vmcs_n::guest_rflags::interrupt_enable_flag::enable();
    vmcs_n::guest_interruptibility_state::blocking_by_sti::disable();
    vmcs_n::guest_interruptibility_state::blocking_by_mov_ss::disable();
}

inline auto
close_interrupt_window()
{ vmcs_n::guest_rflags::interrupt_enable_flag::disable(); }

inline auto
check_vmentry_interrupt_info(uint64_t next)
{
    namespace info_n = vmcs_n::vm_entry_interruption_information;

    CHECK(info_n::vector::get() == next);
    CHECK(info_n::valid_bit::is_enabled());
    CHECK(info_n::interruption_type::get() == info_n::interruption_type::external_interrupt);
}

//extern "C" void _esr0(void) noexcept { }
//extern "C" void _esr1(void) noexcept { }
//extern "C" void _esr2(void) noexcept { }
//extern "C" void _esr3(void) noexcept { }
//extern "C" void _esr4(void) noexcept { }
//extern "C" void _esr5(void) noexcept { }
//extern "C" void _esr6(void) noexcept { }
//extern "C" void _esr7(void) noexcept { }
//extern "C" void _esr8(void) noexcept { }
//extern "C" void _esr9(void) noexcept { }
//extern "C" void _esr10(void) noexcept { }
//extern "C" void _esr11(void) noexcept { }
//extern "C" void _esr12(void) noexcept { }
//extern "C" void _esr13(void) noexcept { }
//extern "C" void _esr14(void) noexcept { }
//extern "C" void _esr15(void) noexcept { }
//extern "C" void _esr16(void) noexcept { }
//extern "C" void _esr17(void) noexcept { }
//extern "C" void _esr18(void) noexcept { }
//extern "C" void _esr19(void) noexcept { }
//extern "C" void _esr20(void) noexcept { }
//extern "C" void _esr21(void) noexcept { }
//extern "C" void _esr22(void) noexcept { }
//extern "C" void _esr23(void) noexcept { }
//extern "C" void _esr24(void) noexcept { }
//extern "C" void _esr25(void) noexcept { }
//extern "C" void _esr26(void) noexcept { }
//extern "C" void _esr27(void) noexcept { }
//extern "C" void _esr28(void) noexcept { }
//extern "C" void _esr29(void) noexcept { }
//extern "C" void _esr30(void) noexcept { }
//extern "C" void _esr31(void) noexcept { }

extern "C" void _isr32(void) noexcept { }
extern "C" void _isr33(void) noexcept { }
extern "C" void _isr34(void) noexcept { }
extern "C" void _isr35(void) noexcept { }
extern "C" void _isr36(void) noexcept { }
extern "C" void _isr37(void) noexcept { }
extern "C" void _isr38(void) noexcept { }
extern "C" void _isr39(void) noexcept { }
extern "C" void _isr40(void) noexcept { }
extern "C" void _isr41(void) noexcept { }
extern "C" void _isr42(void) noexcept { }
extern "C" void _isr43(void) noexcept { }
extern "C" void _isr44(void) noexcept { }
extern "C" void _isr45(void) noexcept { }
extern "C" void _isr46(void) noexcept { }
extern "C" void _isr47(void) noexcept { }
extern "C" void _isr48(void) noexcept { }
extern "C" void _isr49(void) noexcept { }
extern "C" void _isr50(void) noexcept { }
extern "C" void _isr51(void) noexcept { }
extern "C" void _isr52(void) noexcept { }
extern "C" void _isr53(void) noexcept { }
extern "C" void _isr54(void) noexcept { }
extern "C" void _isr55(void) noexcept { }
extern "C" void _isr56(void) noexcept { }
extern "C" void _isr57(void) noexcept { }
extern "C" void _isr58(void) noexcept { }
extern "C" void _isr59(void) noexcept { }
extern "C" void _isr60(void) noexcept { }
extern "C" void _isr61(void) noexcept { }
extern "C" void _isr62(void) noexcept { }
extern "C" void _isr63(void) noexcept { }
extern "C" void _isr64(void) noexcept { }
extern "C" void _isr65(void) noexcept { }
extern "C" void _isr66(void) noexcept { }
extern "C" void _isr67(void) noexcept { }
extern "C" void _isr68(void) noexcept { }
extern "C" void _isr69(void) noexcept { }
extern "C" void _isr70(void) noexcept { }
extern "C" void _isr71(void) noexcept { }
extern "C" void _isr72(void) noexcept { }
extern "C" void _isr73(void) noexcept { }
extern "C" void _isr74(void) noexcept { }
extern "C" void _isr75(void) noexcept { }
extern "C" void _isr76(void) noexcept { }
extern "C" void _isr77(void) noexcept { }
extern "C" void _isr78(void) noexcept { }
extern "C" void _isr79(void) noexcept { }
extern "C" void _isr80(void) noexcept { }
extern "C" void _isr81(void) noexcept { }
extern "C" void _isr82(void) noexcept { }
extern "C" void _isr83(void) noexcept { }
extern "C" void _isr84(void) noexcept { }
extern "C" void _isr85(void) noexcept { }
extern "C" void _isr86(void) noexcept { }
extern "C" void _isr87(void) noexcept { }
extern "C" void _isr88(void) noexcept { }
extern "C" void _isr89(void) noexcept { }
extern "C" void _isr90(void) noexcept { }
extern "C" void _isr91(void) noexcept { }
extern "C" void _isr92(void) noexcept { }
extern "C" void _isr93(void) noexcept { }
extern "C" void _isr94(void) noexcept { }
extern "C" void _isr95(void) noexcept { }
extern "C" void _isr96(void) noexcept { }
extern "C" void _isr97(void) noexcept { }
extern "C" void _isr98(void) noexcept { }
extern "C" void _isr99(void) noexcept { }
extern "C" void _isr100(void) noexcept { }
extern "C" void _isr101(void) noexcept { }
extern "C" void _isr102(void) noexcept { }
extern "C" void _isr103(void) noexcept { }
extern "C" void _isr104(void) noexcept { }
extern "C" void _isr105(void) noexcept { }
extern "C" void _isr106(void) noexcept { }
extern "C" void _isr107(void) noexcept { }
extern "C" void _isr108(void) noexcept { }
extern "C" void _isr109(void) noexcept { }
extern "C" void _isr110(void) noexcept { }
extern "C" void _isr111(void) noexcept { }
extern "C" void _isr112(void) noexcept { }
extern "C" void _isr113(void) noexcept { }
extern "C" void _isr114(void) noexcept { }
extern "C" void _isr115(void) noexcept { }
extern "C" void _isr116(void) noexcept { }
extern "C" void _isr117(void) noexcept { }
extern "C" void _isr118(void) noexcept { }
extern "C" void _isr119(void) noexcept { }
extern "C" void _isr120(void) noexcept { }
extern "C" void _isr121(void) noexcept { }
extern "C" void _isr122(void) noexcept { }
extern "C" void _isr123(void) noexcept { }
extern "C" void _isr124(void) noexcept { }
extern "C" void _isr125(void) noexcept { }
extern "C" void _isr126(void) noexcept { }
extern "C" void _isr127(void) noexcept { }
extern "C" void _isr128(void) noexcept { }
extern "C" void _isr129(void) noexcept { }
extern "C" void _isr130(void) noexcept { }
extern "C" void _isr131(void) noexcept { }
extern "C" void _isr132(void) noexcept { }
extern "C" void _isr133(void) noexcept { }
extern "C" void _isr134(void) noexcept { }
extern "C" void _isr135(void) noexcept { }
extern "C" void _isr136(void) noexcept { }
extern "C" void _isr137(void) noexcept { }
extern "C" void _isr138(void) noexcept { }
extern "C" void _isr139(void) noexcept { }
extern "C" void _isr140(void) noexcept { }
extern "C" void _isr141(void) noexcept { }
extern "C" void _isr142(void) noexcept { }
extern "C" void _isr143(void) noexcept { }
extern "C" void _isr144(void) noexcept { }
extern "C" void _isr145(void) noexcept { }
extern "C" void _isr146(void) noexcept { }
extern "C" void _isr147(void) noexcept { }
extern "C" void _isr148(void) noexcept { }
extern "C" void _isr149(void) noexcept { }
extern "C" void _isr150(void) noexcept { }
extern "C" void _isr151(void) noexcept { }
extern "C" void _isr152(void) noexcept { }
extern "C" void _isr153(void) noexcept { }
extern "C" void _isr154(void) noexcept { }
extern "C" void _isr155(void) noexcept { }
extern "C" void _isr156(void) noexcept { }
extern "C" void _isr157(void) noexcept { }
extern "C" void _isr158(void) noexcept { }
extern "C" void _isr159(void) noexcept { }
extern "C" void _isr160(void) noexcept { }
extern "C" void _isr161(void) noexcept { }
extern "C" void _isr162(void) noexcept { }
extern "C" void _isr163(void) noexcept { }
extern "C" void _isr164(void) noexcept { }
extern "C" void _isr165(void) noexcept { }
extern "C" void _isr166(void) noexcept { }
extern "C" void _isr167(void) noexcept { }
extern "C" void _isr168(void) noexcept { }
extern "C" void _isr169(void) noexcept { }
extern "C" void _isr170(void) noexcept { }
extern "C" void _isr171(void) noexcept { }
extern "C" void _isr172(void) noexcept { }
extern "C" void _isr173(void) noexcept { }
extern "C" void _isr174(void) noexcept { }
extern "C" void _isr175(void) noexcept { }
extern "C" void _isr176(void) noexcept { }
extern "C" void _isr177(void) noexcept { }
extern "C" void _isr178(void) noexcept { }
extern "C" void _isr179(void) noexcept { }
extern "C" void _isr180(void) noexcept { }
extern "C" void _isr181(void) noexcept { }
extern "C" void _isr182(void) noexcept { }
extern "C" void _isr183(void) noexcept { }
extern "C" void _isr184(void) noexcept { }
extern "C" void _isr185(void) noexcept { }
extern "C" void _isr186(void) noexcept { }
extern "C" void _isr187(void) noexcept { }
extern "C" void _isr188(void) noexcept { }
extern "C" void _isr189(void) noexcept { }
extern "C" void _isr190(void) noexcept { }
extern "C" void _isr191(void) noexcept { }
extern "C" void _isr192(void) noexcept { }
extern "C" void _isr193(void) noexcept { }
extern "C" void _isr194(void) noexcept { }
extern "C" void _isr195(void) noexcept { }
extern "C" void _isr196(void) noexcept { }
extern "C" void _isr197(void) noexcept { }
extern "C" void _isr198(void) noexcept { }
extern "C" void _isr199(void) noexcept { }
extern "C" void _isr200(void) noexcept { }
extern "C" void _isr201(void) noexcept { }
extern "C" void _isr202(void) noexcept { }
extern "C" void _isr203(void) noexcept { }
extern "C" void _isr204(void) noexcept { }
extern "C" void _isr205(void) noexcept { }
extern "C" void _isr206(void) noexcept { }
extern "C" void _isr207(void) noexcept { }
extern "C" void _isr208(void) noexcept { }
extern "C" void _isr209(void) noexcept { }
extern "C" void _isr210(void) noexcept { }
extern "C" void _isr211(void) noexcept { }
extern "C" void _isr212(void) noexcept { }
extern "C" void _isr213(void) noexcept { }
extern "C" void _isr214(void) noexcept { }
extern "C" void _isr215(void) noexcept { }
extern "C" void _isr216(void) noexcept { }
extern "C" void _isr217(void) noexcept { }
extern "C" void _isr218(void) noexcept { }
extern "C" void _isr219(void) noexcept { }
extern "C" void _isr220(void) noexcept { }
extern "C" void _isr221(void) noexcept { }
extern "C" void _isr222(void) noexcept { }
extern "C" void _isr223(void) noexcept { }
extern "C" void _isr224(void) noexcept { }
extern "C" void _isr225(void) noexcept { }
extern "C" void _isr226(void) noexcept { }
extern "C" void _isr227(void) noexcept { }
extern "C" void _isr228(void) noexcept { }
extern "C" void _isr229(void) noexcept { }
extern "C" void _isr230(void) noexcept { }
extern "C" void _isr231(void) noexcept { }
extern "C" void _isr232(void) noexcept { }
extern "C" void _isr233(void) noexcept { }
extern "C" void _isr234(void) noexcept { }
extern "C" void _isr235(void) noexcept { }
extern "C" void _isr236(void) noexcept { }
extern "C" void _isr237(void) noexcept { }
extern "C" void _isr238(void) noexcept { }
extern "C" void _isr239(void) noexcept { }
extern "C" void _isr240(void) noexcept { }
extern "C" void _isr241(void) noexcept { }
extern "C" void _isr242(void) noexcept { }
extern "C" void _isr243(void) noexcept { }
extern "C" void _isr244(void) noexcept { }
extern "C" void _isr245(void) noexcept { }
extern "C" void _isr246(void) noexcept { }
extern "C" void _isr247(void) noexcept { }
extern "C" void _isr248(void) noexcept { }
extern "C" void _isr249(void) noexcept { }
extern "C" void _isr250(void) noexcept { }
extern "C" void _isr251(void) noexcept { }
extern "C" void _isr252(void) noexcept { }
extern "C" void _isr253(void) noexcept { }
extern "C" void _isr254(void) noexcept { }
extern "C" void _isr255(void) noexcept { }

#endif
