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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfconstants.h>

#include <hve/pci_register.h>
#include <intrinsics.h>

using bus_type = eapis::pci::bus_type;
using device_type = eapis::pci::device_type;
using func_type = eapis::pci::func_type;
using register_type = eapis::pci::register_type;

static const x64::portio::port_addr_type PORTIO_CONFIG_ADDRESS = 0xCF8;
static const x64::portio::port_addr_type PORTIO_CONFIG_DATA    = 0xCFC;

// PCI configuration space address format: see
// https://wiki.osdev.org/PCI#Configuration_Space_Access_Mechanism_.231

static uint32_t
config_address(bus_type bus, device_type device, func_type func, register_type reg)
{
    const auto ext_bus = static_cast<uint32_t>(bus);
    const auto ext_dev = static_cast<uint32_t>(device);
    const auto ext_func = static_cast<uint32_t>(func);
    const auto ext_reg = static_cast<uint32_t>(reg);

    return ((ext_bus << 16) | (ext_dev << 11) | (ext_func << 8) |
            (ext_reg & 0xfc) | 0x80000000);
}

namespace eapis
{

namespace pci
{

uint8_t
read_register_u8(bus_type bus, device_type device, func_type func, register_type reg)
{
    const auto address = config_address(bus, device, func, reg);

    x64::portio::outd(PORTIO_CONFIG_ADDRESS, address);
    uint32_t fullreg = x64::portio::ind(PORTIO_CONFIG_DATA);

    return gsl::narrow_cast<uint8_t>((fullreg >> ((reg & 3) * 8)) & 0xFF);
}

uint16_t
read_register_u16(bus_type bus, device_type device, func_type func, register_type reg)
{
    const auto address = config_address(bus, device, func, reg);

    x64::portio::outd(PORTIO_CONFIG_ADDRESS, address);
    uint32_t fullreg = x64::portio::ind(PORTIO_CONFIG_DATA);

    return gsl::narrow_cast<uint16_t>((fullreg >> ((reg & 2) * 8)) & 0xFFFF);
}

uint32_t
read_register_u32(bus_type bus, device_type device, func_type func, register_type reg)
{
    const auto address = config_address(bus, device, func, reg);

    x64::portio::outd(PORTIO_CONFIG_ADDRESS, address);
    uint32_t fullreg = x64::portio::ind(PORTIO_CONFIG_DATA);

    return fullreg;
}

void
write_register(bus_type bus, device_type device, func_type func, register_type reg,
               uint32_t value)
{
    const uint32_t address = config_address(bus, device, func, reg);

    x64::portio::outd(PORTIO_CONFIG_ADDRESS, address);
    x64::portio::outd(PORTIO_CONFIG_DATA, value);
}

void
rmw_register_u8(bus_type bus, device_type device, func_type func, register_type reg,
                uint8_t value)
{
    const auto addr32 = gsl::narrow_cast<register_type>(reg & ~0x3u);
    const uint32_t offset = 8 * (reg & 0x3u);
    const uint32_t mask = 0xFFu << offset;

    const uint32_t full_reg = read_register_u32(bus, device, func, addr32);
    const auto full_value = static_cast<uint32_t>(value);
    const uint32_t masked_reg = full_reg & ~mask;
    const uint32_t with_new_value = masked_reg | (full_value << offset);

    write_register(bus, device, func, addr32, with_new_value);
}

void
rmw_register_u16(bus_type bus, device_type device, func_type func, register_type reg,
                 uint16_t value)
{
    const auto addr32 = gsl::narrow_cast<register_type>(reg & ~0x2u);
    const uint32_t offset = 8 * (reg & 0x2u);
    const uint32_t mask = 0xFFFFu << offset;

    const uint32_t full_reg = read_register_u32(bus, device, func, addr32);
    const auto full_value = static_cast<uint32_t>(value);
    const uint32_t masked_reg = full_reg & ~mask;
    const uint32_t with_new_value = masked_reg | (full_value << offset);

    write_register(bus, device, func, addr32, with_new_value);
}

}

}
