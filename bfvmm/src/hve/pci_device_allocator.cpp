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

#include <hve/pci_device_allocator.h>
#include <hve/phys_pci.h>

using bus_type = eapis::pci::bus_type;
using device_type = eapis::pci::device_type;
using func_type = eapis::pci::func_type;
using register_type = eapis::pci::register_type;

using eapis::pci::device_allocator;
using eapis::pci::device_id;

device_allocator::device_allocator()
    : m_buses(256, 0),
      m_bridges_allocated(8192, 0)
{ }

device_allocator::alloc_status
device_allocator::populate_physical()
{
    std::vector<phys_pci> phys_devices;
    phys_pci::enumerate(phys_devices);

    for (auto const &phys_device : phys_devices) {
        device_id device = {
            phys_device.bus(),
            phys_device.device(),
            phys_device.func(),
            phys_device.secondary_bus()
        };

        auto status = check_add(device);

        if (status != alloc_status::success) {
            return status;
        }
    }

    for (auto const &phys_device : phys_devices) {
        device_id device = {
            phys_device.bus(),
            phys_device.device(),
            phys_device.func(),
            phys_device.secondary_bus()
        };

        auto status = add(device);

        if (status != alloc_status::success) {
            throw std::logic_error("device_allocator::check_add() succeeded but add() failed");
        }
    }

    return alloc_status::success;
}

device_allocator::alloc_status
device_allocator::populate_from(device_allocator const &other)
{
    for (size_t bus = 0; bus < m_buses.size(); ++bus) {
        if ((m_buses[bus] & other.m_buses[bus]) != 0) {
            return alloc_status::collision;
        }
    }

    for (size_t bridge_idx = 0; bridge_idx < m_bridges_allocated.size(); ++bridge_idx) {
        if (m_bridges_allocated[bridge_idx] != 0 && other.m_bridges_allocated[bridge_idx] != 0) {
            return alloc_status::collision;
        }
    }

    for (size_t bus = 0; bus < m_buses.size(); ++bus) {
        m_buses[bus] |= other.m_buses[bus];
    }

    for (size_t bridge_idx = 0; bridge_idx < m_bridges_allocated.size(); ++bridge_idx) {
        if (other.m_bridges_allocated[bridge_idx] != 0) {
            m_bridges_allocated[bridge_idx] = other.m_bridges_allocated[bridge_idx];
        }
    }

    return alloc_status::success;
}

device_allocator::alloc_status
device_allocator::add(device_id device)
{
    auto status = check_add(device);

    if (status != alloc_status::success) {
        return status;
    }

    m_buses[device.bus] |= (1u << device.device);

    if (device.secondary_bus != 0) {
        secondary_bus_element(device.bus, device.device) = device.secondary_bus;
    }

    return alloc_status::success;
}

device_allocator::alloc_status
device_allocator::allocate_nonrecursive(bus_type bus, device_id &device, device_type top)
{
    for (device_type dev = 0; dev <= top; ++dev) {
        if ((m_buses[bus] & (1u << dev)) == 0) {
            m_buses[bus] |= (1u << dev);
            device.bus = bus;
            device.device = dev;
            device.func = 0;
            device.secondary_bus = 0;
            return alloc_status::success;
        }
    }

    if (top == 31 || (((1u << (top + 1)) - 1u) | m_buses[bus]) == 0xFFFFFFFFu) {
        return alloc_status::bus_full;
    }
    else {
        return alloc_status::bus_almost_full;
    }
}

device_allocator::alloc_status
device_allocator::allocate_recursive(bus_type bus, device_id &device, device_type top)
{
    if (allocate_nonrecursive(bus, device, top) == alloc_status::success) {
        return alloc_status::success;
    }

    for (device_type dev = 0; dev <= 31; ++dev) {
        bus_type secbus = secondary_bus_element(bus, dev);

        if (secbus != 0) {
            device_allocator::alloc_status status = allocate_recursive(secbus, device, top);

            if (status == alloc_status::success) {
                return alloc_status::success;
            }
        }
    }

    if (top == 31 || (((1u << (top + 1)) - 1u) | m_buses[bus]) == 0xFFFFFFFFu) {
        return alloc_status::bus_full;
    }
    else {
        return alloc_status::bus_almost_full;
    }
}

device_allocator::alloc_status
device_allocator::allocate(device_id &device)
{
    return allocate_recursive(0, device, 30);
}

device_allocator::alloc_status
device_allocator::allocate(bus_type bus, device_id &device)
{
    return allocate_nonrecursive(bus, device, 30);
}

device_allocator::alloc_status
device_allocator::allocate_bridge(device_id &device)
{
    bus_type next_bus = next_secondary();

    if (next_bus == 0) {
        return alloc_status::full;
    }

    auto status = allocate_recursive(0, device, 31);

    if (status == alloc_status::success) {
        device.secondary_bus = next_bus;
        secondary_bus_element(device.bus, device.device) = device.secondary_bus;
    }

    return status;
}

device_allocator::alloc_status
device_allocator::allocate_bridge(bus_type bus, device_id &device)
{
    bus_type next_bus = next_secondary();

    if (next_bus == 0) {
        return alloc_status::full;
    }

    auto status = allocate_nonrecursive(bus, device, 31);

    if (status == alloc_status::success) {
        device.secondary_bus = gsl::narrow_cast<bus_type>(next_bus);
        secondary_bus_element(device.bus, device.device) = device.secondary_bus;
    }

    return status;
}

bool
device_allocator::contains(device_id device) const
{
    check_device(device.device);

    return (m_buses[device.bus] & (1u << device.device)) != 0;
}

void
device_allocator::deallocate(device_id device)
{
    check_device(device.device);

    bus_type &secbus = secondary_bus_element(device.bus, device.device);

    if (secbus != 0) {
        m_buses[secbus] = 0;
        secbus = 0;
    }

    m_buses[device.bus] &= ~(1u << device.device);
}

void
device_allocator::clear()
{
    for (auto &i : m_buses) {
        i = 0;
    }

    for (auto &i : m_bridges_allocated) {
        i = 0;
    }
}

void
device_allocator::enumerate(std::vector<device_id> &devices) const
{
    for (size_t bus = 0; bus <= 255; ++bus) {
        for (device_type dev = 0; dev <= 31; ++dev) {
            if ((m_buses[bus] & (1u << dev)) != 0) {
                device_id device;
                device.bus = gsl::narrow_cast<bus_type>(bus);
                device.device = dev;
                device.func = 0;
                device.secondary_bus = secondary_bus_element(device.bus, device.device);
                devices.push_back(device);
            }
        }
    }
}

bus_type &
device_allocator::secondary_bus_element(bus_type bus, device_type device)
{
    check_device(device);

    size_t bus_extended = static_cast<size_t>(bus);
    size_t dev_extended = static_cast<size_t>(device);

    return m_bridges_allocated[(dev_extended << 8) | bus_extended];
}

bus_type
device_allocator::secondary_bus_element(bus_type bus, device_type device) const
{
    check_device(device);

    size_t bus_extended = static_cast<size_t>(bus);
    size_t dev_extended = static_cast<size_t>(device);

    return m_bridges_allocated[(dev_extended << 8) | bus_extended];
}

bus_type
device_allocator::next_secondary() const
{
    for (size_t i = 1; i <= 255; ++i) {
        bool found = false;

        for (auto j : m_bridges_allocated) {
            if (i == j) {
                found = true;
                break;
            }
        }

        if (!found) {
            return gsl::narrow_cast<bus_type>(i);
        }
    }

    return 0;
}

void
device_allocator::check_device(device_type device) const
{
    if (device > 31) {
        throw std::logic_error("invalid PCI device number");
    }
}

device_allocator::alloc_status
device_allocator::check_add(device_id device) const
{
    check_device(device.device);

    if (device.secondary_bus != 0) {
        for (auto const &i : m_bridges_allocated) {
            if (i == device.secondary_bus) {
                return alloc_status::collision;
            }
        }

        if (secondary_bus_element(device.bus, device.device) != 0) {
            return alloc_status::collision;
        }
    }

    if ((m_buses[device.bus] & (1u << device.device)) != 0) {
        return alloc_status::collision;
    }

    return alloc_status::success;
}
