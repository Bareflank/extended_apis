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
#include <hve/arch/intel_x64/phys_xapic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;
namespace lapic_n = ::intel_x64::lapic;

alignas(4096) uint8_t g_xapic[4096U] = {0U};
uintptr_t g_base = reinterpret_cast<uintptr_t>(g_xapic);

TEST_CASE("phys_xapic: constructor")
{
    auto apic = phys_xapic(g_base);

    CHECK(apic.base() == g_base);
    CHECK_THROWS(phys_xapic(0x1U));
}

TEST_CASE("phys_xapic: relocate")
{
    auto apic = phys_xapic(0U);

    CHECK_THROWS(apic.relocate(0xCAFEBABEU));
    apic.relocate(0xCAFEB000U);
    CHECK(apic.base() == 0xCAFEB000U);
}

TEST_CASE("phys_xapic: interrupts")
{
    auto apic = phys_xapic(g_base);

    x64::rflags::interrupt_enable_flag::disable();

    CHECK(x64::rflags::interrupt_enable_flag::is_disabled());
    apic.enable_interrupts();
    CHECK(x64::rflags::interrupt_enable_flag::is_enabled());
    apic.disable_interrupts();
    CHECK(x64::rflags::interrupt_enable_flag::is_disabled());
}

TEST_CASE("phys_xapic: read_register")
{
    auto apic = phys_xapic(g_base);
    auto id_addr = g_base + 0x20U;
    auto off = lapic_register::mem_addr_to_offset(id_addr);

    g_xapic[off << 4U] = 0xEEU;
    CHECK(apic.read_register(off) == 0xEEU);
}

TEST_CASE("phys_xapic: write_register")
{
    auto apic = phys_xapic(g_base);
    auto icr0_addr = g_base + 0x300U;
    auto off = lapic_register::mem_addr_to_offset(icr0_addr);

    apic.write_register(off, 0xEDU);
    CHECK(g_xapic[off << 4U] == 0xEDU);
}

TEST_CASE("phys_xapic::read_id")
{
    auto apic = phys_xapic(g_base);
    auto id_addr = g_base + 0x020U;
    auto off = lapic_register::mem_addr_to_offset(id_addr);

    apic.write_register(off, 0xEDU);
    CHECK(apic.read_id() == 0xEDU);
}

TEST_CASE("phys_xapic::read_version")
{
    auto apic = phys_xapic(g_base);
    auto ver_addr = g_base + 0x030U;
    auto off = lapic_register::mem_addr_to_offset(ver_addr);

    apic.write_register(off, 0xEDU);
    CHECK(apic.read_version() == 0xEDU);
}

TEST_CASE("phys_xapic::read_tpr")
{
    auto apic = phys_xapic(g_base);

    g_cr8 = 0x4U;
    CHECK(apic.read_tpr() == (g_cr8 << 4U));
}

TEST_CASE("phys_xapic::read_svr")
{
    auto apic = phys_xapic(g_base);
    auto svr_addr = g_base + 0x0F0U;
    auto off = lapic_register::mem_addr_to_offset(svr_addr);

    apic.write_register(off, 0xEDU);
    CHECK(apic.read_svr() == 0xEDU);
}

TEST_CASE("phys_xapic::read_icr")
{
    auto apic = phys_xapic(g_base);
    auto icr0 = g_base + 0x300U;
    auto icr1 = g_base + 0x310U;
    auto off0 = lapic_register::mem_addr_to_offset(icr0);
    auto off1 = lapic_register::mem_addr_to_offset(icr1);

    apic.write_register(off1, 0xEDU);
    apic.write_register(off0, 0xCC00U);
    CHECK(apic.read_icr() == 0xED0000CC00U);
}

TEST_CASE("phys_xapic::write_eoi")
{
    auto apic = phys_xapic(g_base);
    auto eoi_addr = g_base + 0x0B0U;
    auto off = lapic_register::mem_addr_to_offset(eoi_addr);
    auto ptr = reinterpret_cast<uint32_t *>(eoi_addr);

    *ptr = 0x11223344U;
    apic.write_eoi();
    CHECK(*ptr == 0x0U);
}

TEST_CASE("phys_xapic::write_tpr")
{
    auto apic = phys_xapic(g_base);

    g_cr8 = 0U;
    apic.write_tpr(0xF0U);
    CHECK(g_cr8 == (0xF0U >> 4U));
}

TEST_CASE("phys_xapic::write_svr")
{
    auto apic = phys_xapic(g_base);
    auto svr_addr = g_base + 0x0F0U;
    auto off = lapic_register::mem_addr_to_offset(svr_addr);
    auto ptr = reinterpret_cast<uint32_t *>(svr_addr);

    *ptr = 0x00CC7722U;
    apic.write_svr(0U);
    CHECK(*ptr == 0U);
}

TEST_CASE("phys_xapic::write_icr")
{
    auto apic = phys_xapic(g_base);
    auto icr0 = g_base + 0x300U;
    auto icr1 = g_base + 0x310U;
    auto off0 = lapic_register::mem_addr_to_offset(icr0);
    auto off1 = lapic_register::mem_addr_to_offset(icr1);
    auto ptr0 = reinterpret_cast<uint32_t *>(icr0);
    auto ptr1 = reinterpret_cast<uint32_t *>(icr1);

    apic.write_icr(0x1100ED0099U);
    CHECK(*ptr0 == 0x00ED0099U);
    CHECK(*ptr1 == 0x11U);
}

TEST_CASE("phys_xapic::write_self_ipi")
{
    auto apic = phys_xapic(g_base);
    auto icr0 = g_base + 0x300U;
    auto off0 = lapic_register::mem_addr_to_offset(icr0);
    auto ptr0 = reinterpret_cast<uint32_t *>(icr0);

    apic.write_self_ipi(0xFEU);
    CHECK((*ptr0 & 0xFFU) == 0xFEU);
}

}
}

#endif
