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

}
