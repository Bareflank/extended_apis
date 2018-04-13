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

#include <hve/phys_pci.h>
#include <intrinsics.h>

using eapis::pci::phys_pci;
using eapis::pci::bar;

using bus_type = eapis::pci::bus_type;
using device_type = eapis::pci::device_type;
using func_type = eapis::pci::func_type;
using register_type = eapis::pci::register_type;

namespace eapis
{

static void enumerate_pci_one_bus(std::vector<phys_pci> &vect, bus_type bus);
static void enumerate_pci_one_device(std::vector<phys_pci> &vect, bus_type bus,
                                     device_type device);
static void enumerate_pci_one_function(std::vector<phys_pci> &vect, bus_type bus,
                                       device_type device, func_type func);
static bus_type get_secondary_bus(bus_type bus, device_type device, func_type func);

void pci::phys_pci::enumerate(std::vector<phys_pci> &vect)
{
    phys_pci first_host_controller(0, 0, 0);

    if ((first_host_controller.header_type() & 0x80) == 0) {
        enumerate_pci_one_bus(vect, 0);
    }
    else {
        for (func_type func = 0; func < 8; ++func) {
            phys_pci host_controller(0, 0, func);

            if (host_controller.vendor_id() != 0xFFFF) {
                break;
            }

            enumerate_pci_one_bus(vect, func);
        }
    }
}

static void enumerate_pci_one_bus(std::vector<phys_pci> &vect, bus_type bus)
{
    for (device_type device = 0; device < 32; ++device) {
        enumerate_pci_one_device(vect, bus, device);
    }
}

static void enumerate_pci_one_device(std::vector<phys_pci> &vect, bus_type bus,
                                     device_type device)
{
    phys_pci pci_device(bus, device, 0);

    auto vendor = pci_device.vendor_id();
    if (vendor == 0xFFFF) {
        return;
    }

    enumerate_pci_one_function(vect, bus, device, 0);

    if ((pci_device.header_type() & 0x80) != 0) {
        for (func_type func = 0; func < 8; ++func) {
            phys_pci pci_func(bus, device, func);

            if (pci_func.vendor_id() != 0xFFFF && func > 0) {
                enumerate_pci_one_function(vect, bus, device, func);
            }
        }
    }
}
static void enumerate_pci_one_function(std::vector<phys_pci> &vect, bus_type bus,
                                       device_type device, func_type func)
{
    phys_pci pci_func(bus, device, func);

    if (pci_func.device_class() == 0x06 && pci_func.device_subclass() == 0x04) {
        bus_type sec_bus = get_secondary_bus(bus, device, func);
        enumerate_pci_one_bus(vect, sec_bus);
    }

    vect.push_back(pci_func);
}

static bus_type get_secondary_bus(bus_type bus, device_type device,
                                  func_type func)
{
    phys_pci pci_func(bus, device, func);
    return pci_func.read_register_u8(0x19);
}

enum bar::bar_type
bar::compute_type() const {
    const uint8_t header_type = m_device.header_type() & 0x7F;
    unsigned int bar_count;

    switch (header_type)
    {
        case 0:
            bar_count = 6;
            break;
        case 1:
            bar_count = 2;
            break;
        default:
            bar_count = 0;
    }

    if (m_index >= bar_count)
    {
        return bar_invalid;
    }

    if (m_index > 0)
    {
        bar previous(m_device, m_index - 1u);

        if (previous.type() == bar_memory_64bit) {
            return bar_invalid;
        }
    }

    uint32_t contents = m_device.bar(m_index);

    if ((contents & 0x1) != 0)
    {
        return bar_io;
    }
    else if ((contents & 0x6) == 0x0)
    {
        return bar_memory_32bit;
    }
    else if ((contents & 0x6) == 0x4)
    {
        if (m_index >= bar_count - 1u) {
            return bar_invalid;
        }
        else {
            return bar_memory_64bit;
        }
    }
    else
    {
        return bar_invalid;
    }
}

uintptr_t
bar::base_address() const
{
    uintptr_t contents = static_cast<uintptr_t>(m_device.bar(m_index));

    uintptr_t addr = contents & mask();

    if (m_type == bar_memory_64bit) {
        uintptr_t next_contents = static_cast<uintptr_t>(m_device.bar(m_index + 1u));
        addr |= (next_contents << 32);
    }

    return addr;
}

uintptr_t
bar::region_length()
{
    if (m_type == bar_memory_64bit) {
        return region_length_64();
    }
    else if (m_type == bar_invalid) {
        return 0;
    }

    uint32_t orig_contents = m_device.bar(m_index);
    m_device.set_bar(m_index, 0xFFFFFFFF);
    uint32_t region_bits = m_device.bar(m_index);
    m_device.set_bar(m_index, orig_contents);

    uintptr_t len = ~(0xFFFFFFFF00000000uLL | static_cast<uintptr_t>(region_bits & mask())) + 1uLL;

    if (m_type == bar_io) {
        len &= 0xFFFF;
    }

    return len;
}

uintptr_t
bar::region_length_64()
{
    uint32_t orig_contents[2] = {
        m_device.bar(m_index),
        m_device.bar(m_index + 1)
    };

    m_device.set_bar(m_index, 0xFFFFFFFF);
    m_device.set_bar(m_index + 1, 0xFFFFFFFF);

    uint32_t region_bits[2] = {
        m_device.bar(m_index),
        m_device.bar(m_index + 1)
    };

    m_device.set_bar(m_index, orig_contents[0]);
    m_device.set_bar(m_index + 1, orig_contents[1]);

    const uint64_t mask = 0xFFFFFFFFFFFFFFF0;
    const uint64_t merged = static_cast<uint64_t>(region_bits[0]) | (static_cast<uint64_t>(region_bits[1]) << 32);
    const uint64_t masked = merged & mask;

    return static_cast<uintptr_t>(~masked + 1);
}

bool
bar::prefetchable() const
{
    uintptr_t contents = static_cast<uintptr_t>(m_device.bar(m_index));

    switch (m_type) {
        case bar_memory_32bit:
        case bar_memory_64bit:
            return (contents & 0x8) != 0;

        case bar_io:
        case bar_invalid:
        default:
            return false;
    }
}

void
bar::set_base_address(uintptr_t address)
{
    const uint32_t lower_mask = mask();

    if (lower_mask == 0) {
        return;
    }

    const uint32_t orig_contents = m_device.bar(m_index);
    const uint32_t lower_addr = gsl::narrow_cast<uint32_t>(address & lower_mask);
    const uint32_t new_contents = (orig_contents & ~lower_mask) | lower_addr;
    m_device.set_bar(m_index, new_contents);

    if (m_type == bar_memory_64bit) {
        m_device.set_bar(m_index + 1, gsl::narrow_cast<uint32_t>(address >> 32));
    }
}

uint32_t
bar::mask() const
{
    switch (m_type) {
        case bar_memory_32bit:
        case bar_memory_64bit:
            return 0xFFFFFFF0;

        case bar_io:
            return 0xFFFFFFFC;

        case bar_invalid:
        default:
            return 0;
    }
}

}
