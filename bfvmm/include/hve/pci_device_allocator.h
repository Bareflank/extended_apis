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

#ifndef PCI_DEVICE_ALLOCATOR_H
#define PCI_DEVICE_ALLOCATOR_H

#include "pci_register.h"

namespace eapis
{

namespace pci
{

/// Allocator for unique PCI device IDs, both physical and virtual
class device_allocator
{
public:

    /// Status of the allocator after an allocation attempt
    enum class alloc_status {
        /// Device was allocated successfully.
        success,

        /// A specific device ID was requested, but that ID already exists.
        collision,

        /// A non-bridge device was requested but there is only one remaining
        /// available device ID on the bus. The last ID is left open to create a
        /// new bridge. If a specific bus is not required, the remedy for this
        /// is to allocate a new bridge and try again.
        bus_almost_full,

        /// There are no remaining devices on the bus. If a bus was specified,
        /// it is full; if no bus was specified, there are no available device
        /// IDs on any existing bus. The remedy for this is to deallocate a
        /// device first, then try again.
        bus_full,

        /// There are no remaining devices on any bus and there are no remaining
        /// buses on the system.
        full,
    };


    /// Create a new, empty allocator.
    device_allocator();

    /// @cond

    device_allocator(device_allocator &&) noexcept = default;
    device_allocator &operator=(device_allocator &&) noexcept = default;

    device_allocator(const device_allocator &) = delete;
    device_allocator &operator=(const device_allocator &) = delete;

    /// @endcond

    /// Populate this allocator from the local system's devices
    /// @return `success` or `collision`. On collision, the allocator
    /// has not been modified.
    alloc_status populate_physical();

    /// Populate this allocator from another allocator
    /// @param other another allocator from which devices will be copied
    /// @return `success` or `collision`. On collision, the allocator
    /// has not been modified.
    alloc_status populate_from(device_allocator const &other);

    /// Add a specific device to this allocator
    /// @param device specific device to add
    /// @return `success` or `collision`. On collision, the allocator
    /// has not been modified.
    alloc_status add(device_id device);

    /// Get a new device on the next available bus.
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @return `success` or an error code.
    alloc_status allocate(device_id &device);

    /// Get a new device on the specified bus.
    /// @param bus bus on which device will be allocated. The bus must exist in the allocator.
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @return `success` or an error code.
    alloc_status allocate(bus_type bus, device_id &device);

    /// Create a new bus, allocating a bus-bus bridge.
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @return `success` or an error code.
    alloc_status allocate_bridge(device_id &device);

    /// Create a new bus, allocating a bus-bus bridge on the specified existing bus.
    /// @param bus bus on which device will be allocated. The bus must exist in the allocator.
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @return `success` or an error code.
    alloc_status allocate_bridge(bus_type bus, device_id &device);

    /// Return whether this allocator contains a given device
    /// @param device PCI device ID to test for
    /// @return true iff the device has been allocated
    bool contains(device_id device) const;

    /// Deallocate a device. If device is a bus-bus bridge, all devices on the
    /// secondary bus will also be deallocated.
    /// @param device PCI device ID to deallocate
    void deallocate(device_id device);

    /// Clear all allocated and populated devices
    void clear();

    /// Fill a vector with all devices this allocator contains
    /// @param devices vector to which all allocated devices will be added
    void enumerate(std::vector<device_id> &devices) const;

private:
    /// Bitmaps, one bit per device, for each bus
    std::vector<uint32_t> m_buses;

    /// Secondary bus number for each bridge, stored at index (device << 8) | bus
    std::vector<bus_type> m_bridges_allocated;

    /// Access the element in m_bridges_allocated for a given device
    /// @param device device number (must be <= 31)
    /// @param bus bus number
    /// @throws std::logic_error if device > 31
    bus_type &secondary_bus_element(bus_type bus, device_type device);

    /// Access the element in m_bridges_allocated for a given device
    /// @param device device number (must be <= 31)
    /// @param bus bus number
    /// @throws std::logic_error if device > 31
    bus_type secondary_bus_element(bus_type bus, device_type device) const;

    /// Find the next available secondary bus number
    /// @return next available secondary bus, or 0 if none
    bus_type next_secondary() const;

    /// Validate a device number and throw an exception if invalid.
    /// @param device device number (should be <= 31)
    /// @throws std::logic_error if device > 31
    void check_device(device_type device) const;

    /// Allocate a device, recursing on bridges.
    /// @param bus starting bus
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @param top maximum device ID to allocate
    /// @return `success` or an error code
    alloc_status allocate_recursive(bus_type bus, device_id &device, device_type top);

    /// Allocate a device on one bus
    /// @param bus bus
    /// @param device will be populated with the allocated device, or unmodified on error
    /// @param top maximum device ID to allocate
    /// @return `success` or an error code
    alloc_status allocate_nonrecursive(bus_type bus, device_id &device, device_type top);

    /// Check whether a specific device can be added to this allocator. Never modifies.
    /// @return `success` or `collision`.
    alloc_status check_add(device_id device) const;
};

}
}

#endif
