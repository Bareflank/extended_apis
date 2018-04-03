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

#ifndef PCI_REGISTER_H
#define PCI_REGISTER_H

namespace eapis
{

/// PCI configuration access
namespace pci
{

/// Type of geographic bus index
using bus_type = uint8_t;

/// Type of geographic device index. Should be <= 31
using device_type = uint8_t;

/// Type of geographic function index. Should be <= 7
using func_type = uint8_t;

/// Type of register index. Should be <= 0x3F
using register_type = uint8_t;

///
/// @brief Read 8 bits from a geographically addressed register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
///
/// @return contents of the register, or 0xFF for nonexistent devices
///
uint8_t
read_register_u8(bus_type bus, device_type device, func_type func, register_type reg);

///
/// @brief Read 16 bits from a geographically addressed register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F, reg is 16-bit aligned
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
///
/// @return contents of the register, or 0xFFFF for nonexistent devices
///
uint16_t
read_register_u16(bus_type bus, device_type device, func_type func, register_type reg);

///
/// @brief Read 32 bits from a geographically addressed register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F, reg is 32-bit aligned
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
///
/// @return contents of the register, or 0xFFFFFFFF for nonexistent devices
///
uint32_t
read_register_u32(bus_type bus, device_type device, func_type func, register_type reg);

///
/// @brief Write 32 bits to a geographically addressed register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F, reg is 32-bit aligned
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
/// @param value value to write
///
void
write_register(bus_type bus, device_type device, func_type func, register_type reg, uint32_t value);

///
/// @brief Perform an 8-bit read-modify-write operation on a geographically addressed 32-bit register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
/// @param value value to write
///
void rmw_register_u8(bus_type bus, device_type device, func_type func, register_type reg, uint8_t value);

///
/// @brief Perform a 16-bit read-modify-write operation on a geographically addressed 32-bit register.
///
/// @expects bus <= 255, device <= 31, func <= 7, reg <= 0x3F, reg is 16-bit aligned
/// @ensures
///
/// @param bus PCI bus number
/// @param device Device number on the bus
/// @param func Function, for multifunction devices (or 0)
/// @param reg register index in bytes
/// @param value value to write
///
void rmw_register_u16(bus_type bus, device_type device, func_type func, register_type reg, uint16_t value);

}

}

#endif
