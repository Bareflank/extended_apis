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

// We need a more complicated implementation of _ind and _outd
// that implement PCI configuration space in a second map.
#define _ind _simple_ind
#define _outd _simple_outd
#include <support/arch/intel_x64/test_support.h>
#undef _ind
#undef _outd

#include <hve/phys_pci.h>

#define PORTIO_CONFIG_ADDRESS   0xCF8
#define PORTIO_CONFIG_DATA      0xCFC

#define BAR_TEST_REGION_LENGTH  0x8000u

#define DEVICE_1_2_3            0x80011300

std::map<uint32_t, uint32_t> g_pci_config_space;

static uint32_t intercept_bar_write(uint32_t addr, uint32_t value);

extern "C" uint32_t
_ind(uint16_t port) noexcept
{
    if (port == PORTIO_CONFIG_DATA) {
        auto it = g_pci_config_space.find(g_ports[PORTIO_CONFIG_ADDRESS]);
        if (it == g_pci_config_space.end()) {
            return 0xFFFFFFFF;
        }
        else {
            return it->second;
        }
    }
    else {
        return g_ports[port];
    }
}

/// Modified test _outd with the following additional features:
///
/// - If writing to 0xCFC (PCI config data), redirect to a second map representing
///   PCI config space.
/// - If the PCI config space address represents a BAR, pass on to
///   intercept_bar_write() to allow the region length query to be tested.
extern "C" void
_outd(uint16_t port, uint32_t value) noexcept
{
    if (port == PORTIO_CONFIG_DATA) {
        uint32_t addr = g_ports[PORTIO_CONFIG_ADDRESS];
        bool maybe_bar = (addr & 0xfc) >= 0x10 && (addr & 0xfc) <= 0x24;

        uint32_t header_type_field = (addr & ~0xFCu) | 0x0Cu;
        uint32_t header_type = (g_pci_config_space[header_type_field] & 0x007F0000u) >> 16;

        g_pci_config_space[addr] = value;

        if (maybe_bar) {
            uint32_t bar_index = ((addr & 0xfc) - 0x10) / 4;

            if ((header_type == 0 && bar_index <= 5) ||
                (header_type == 1 && bar_index <= 1)) {

                g_pci_config_space[addr] = intercept_bar_write(addr, value);
            }
        }
    }

    g_ports[port] = value;
}

static uint32_t
intercept_bar_write(uint32_t addr, uint32_t value)
{
    if (value == 0xFFFFFFFF) {
        if (addr & 0x4) {
            // Odd BAR, assume second half of 64-bit
            return 0xFFFFFFFF;
        }
        else {
            uint32_t old_value = g_pci_config_space[addr];
            return (~(BAR_TEST_REGION_LENGTH - 1u) & 0xFFFFFFFE) | (old_value & 0x1);
        }
    }
    else {
        return value;
    }
}

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
        g_pci_config_space.clear();
    });
}

static void
init_all_config_space()
{
    for (uint32_t reg = 0; reg <= 0x3C; reg += 4) {
        uint32_t addr = DEVICE_1_2_3 | reg;
        g_pci_config_space[addr] = 0xaabbccdd;
    }

    g_ports[PORTIO_CONFIG_DATA] = 0xaabbccdd;
}

namespace eapis
{
namespace pci
{

TEST_CASE("pci_test_support")
{
    CHECK(reg_from_full_addr(0xaabbccdd) == 0xdd);
    CHECK_NOTHROW(init_all_config_space());
    CHECK(g_ports[PORTIO_CONFIG_DATA] == 0xaabbccdd);

    CHECK_NOTHROW(_outd(1, 2));
    CHECK(_ind(1) == 2);

    CHECK_NOTHROW(_outd(PORTIO_CONFIG_ADDRESS, 0xABAD1DEA));
    CHECK(_ind(PORTIO_CONFIG_DATA) == 0xFFFFFFFF);

    // Set up a very simple header and check that BAR writes are intercepted
    CHECK_NOTHROW(_outd(PORTIO_CONFIG_ADDRESS, 0x0000000C));
    CHECK_NOTHROW(_outd(PORTIO_CONFIG_DATA,    0x00000000));
    CHECK_NOTHROW(_outd(PORTIO_CONFIG_ADDRESS, 0x00000010));
    CHECK_NOTHROW(_outd(PORTIO_CONFIG_DATA,    0xFFFFFFFF));
    CHECK(_ind(PORTIO_CONFIG_DATA) != 0xFFFFFFFF);

    for (uint32_t reg = 0; reg <= 0x3C; reg += 4) {
        CHECK(g_pci_config_space[DEVICE_1_2_3 | reg] == 0xaabbccdd);
    }

    {
        auto ___ = cleanup();
    }

    CHECK(g_pci_config_space[DEVICE_1_2_3] == 0);

}

}

}
