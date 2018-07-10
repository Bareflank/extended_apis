//
// Bareflank Extended APIs
//
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

#include <intrinsics.h>

#include <hve/arch/intel_x64/hve.h>
#include <hve/arch/intel_x64/apic/phys_x2apic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs = ::intel_x64::msrs;
namespace lapic = ::intel_x64::lapic;

TEST_CASE("phys_x2apic: interrupts")
{
    auto apic = phys_x2apic();

    x64::rflags::interrupt_enable_flag::disable();

    CHECK(x64::rflags::interrupt_enable_flag::is_disabled());
    apic.enable_interrupts();
    CHECK(x64::rflags::interrupt_enable_flag::is_enabled());
    apic.disable_interrupts();
    CHECK(x64::rflags::interrupt_enable_flag::is_disabled());
}

TEST_CASE("phys_x2apic: read_register")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_apicid::addr;
    auto off = lapic::offset::from_msr_addr(addr);

    g_msrs[addr] = 0xEEU;
    CHECK(apic.read_register(off) == 0xEEU);
}

TEST_CASE("phys_x2apic: write_register")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_eoi::addr;
    auto off = lapic::offset::from_msr_addr(addr);

    g_msrs[addr] = 0xFFFFU;
    apic.write_register(off, 0U);
    CHECK(g_msrs[addr] == 0U);
}

TEST_CASE("phys_x2apic::read_id")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_apicid::addr;

    g_msrs[addr] = 0xBFU;
    CHECK(apic.read_id() == 0xBFU);
}

TEST_CASE("phys_x2apic::read_version")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_version::addr;

    g_msrs[addr] = 0xBFU;
    CHECK(apic.read_version() == 0xBFU);
}

TEST_CASE("phys_x2apic::read_tpr")
{
    auto apic = phys_x2apic();

    g_cr8 = 0x1U;
    CHECK(apic.read_tpr() == (g_cr8 << 4U));
}

TEST_CASE("phys_x2apic::read_svr")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_sivr::addr;

    g_msrs[addr] = 0xF00DU;
    CHECK(apic.read_svr() == 0xF00DU);
}

TEST_CASE("phys_x2apic::read_icr")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_icr::addr;

    g_msrs[addr] = 0xBEEFU;
    CHECK(apic.read_icr() == 0xBEEFU);
}

TEST_CASE("phys_x2apic::write_eoi")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_eoi::addr;

    g_msrs[addr] = 0xFFFFU;
    apic.write_eoi();
    CHECK(g_msrs[addr] == 0U);
}

TEST_CASE("phys_x2apic::write_tpr")
{
    auto apic = phys_x2apic();

    g_cr8 = 0U;
    apic.write_tpr(0xF0U);
    CHECK(g_cr8 == (0xF0U >> 4U));
}

TEST_CASE("phys_x2apic::write_svr")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_sivr::addr;

    g_msrs[addr] = 0xFFFFU;
    apic.write_svr(0U);
    CHECK(g_msrs[addr] == 0U);
}


TEST_CASE("phys_x2apic::write_icr")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_icr::addr;

    g_msrs[addr] = 0xFFFFU;
    apic.write_icr(0U);
    CHECK(g_msrs[addr] == 0U);
}

TEST_CASE("phys_x2apic::write_self_ipi")
{
    auto apic = phys_x2apic();
    auto addr = msrs::ia32_x2apic_self_ipi::addr;

    g_msrs[addr] = 0x0U;
    apic.write_self_ipi(0xFEU);
    CHECK(g_msrs[addr] == 0xFEU);
}

}
}

#endif
