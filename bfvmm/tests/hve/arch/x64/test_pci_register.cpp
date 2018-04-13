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
#include <support/arch/intel_x64/test_support.h>

#include <hve/pci_register.h>

#define PORTIO_CONFIG_ADDRESS 0xCF8
#define PORTIO_CONFIG_DATA    0xCFC

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace pci
{

static uint32_t
reg_from_full_addr(uint32_t full_addr)
{
    return full_addr & 0xff;
}

static auto
cleanup()
{
    return gsl::finally([&] {
        g_ports.clear();
    });
}

TEST_CASE("pci_register test support")
{
    CHECK(reg_from_full_addr(0xaabbccdd) == 0xdd);

    g_ports[0x123] = 0x456;

    {
        auto ___ = cleanup();
    }

    CHECK(g_ports[0x123] == 0);
}

TEST_CASE("pci::read_register_uN(bus, device, func, reg)")
{
    auto ___ = cleanup();

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    CHECK(read_register_u32(1, 2, 3, 4) == 0xaabbccdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    CHECK(read_register_u16(1, 2, 3, 4) == 0xccdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
    CHECK(read_register_u16(1, 2, 3, 6) == 0xaabb);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    CHECK(read_register_u8(1, 2, 3, 4) == 0xdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
    CHECK(read_register_u8(1, 2, 3, 5) == 0xcc);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
    CHECK(read_register_u8(1, 2, 3, 6) == 0xbb);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
    CHECK(read_register_u8(1, 2, 3, 7) == 0xaa);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
}

TEST_CASE("pci::write_register(bus, device, func, reg, value)")
{
    auto ___ = cleanup();
    const uint32_t data = 0x12345678;
    CHECK_NOTHROW(write_register(1, 2, 3, 4, data));
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0x12345678);
}

TEST_CASE("pci::rmw_register_uN(bus, device, func, reg, value)")
{
    auto ___ = cleanup();

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u8(1, 2, 3, 4, 0xff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xaabbccff);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u8(1, 2, 3, 5, 0xff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xaabbffdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u8(1, 2, 3, 6, 0xff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xaaffccdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u8(1, 2, 3, 7, 0xff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xffbbccdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u16(1, 2, 3, 4, 0xffff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xaabbffff);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
    rmw_register_u16(1, 2, 3, 6, 0xffff);
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xffffccdd);
    CHECK(g_ports[PORTIO_CONFIG_ADDRESS] == 0x80011304);
}


}
}

#endif
