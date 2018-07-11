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

#include "arch/x64/pci_test_support.h"
#include <hve/pci_device_allocator.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace pci
{

TEST_CASE("Empty device_allocator")
{
    std::vector<device_id> enumerated;
    device_allocator alloc{};

    CHECK_NOTHROW(alloc.enumerate(enumerated));
    CHECK(enumerated.empty());
}

TEST_CASE("device_allocator::add,contains,deallocate,clear")
{
    device_id device = { 1, 2, 3, 0 };
    device_allocator alloc{};

    CHECK(!alloc.contains(device));
    CHECK(alloc.add(device) == device_allocator::alloc_status::success);
    CHECK(alloc.contains(device));
    CHECK(alloc.add(device) == device_allocator::alloc_status::collision);
    CHECK(alloc.contains(device));

    CHECK_NOTHROW(alloc.deallocate(device));
    CHECK(!alloc.contains(device));
    CHECK(alloc.add(device) == device_allocator::alloc_status::success);
    CHECK(alloc.contains(device));

    CHECK_NOTHROW(alloc.clear());
    CHECK(!alloc.contains(device));
}

TEST_CASE("device_allocator::populate_from")
{
    device_id device = { 1, 2, 3, 0 };
    device_allocator alloc1{};
    device_allocator alloc2{};

    CHECK(alloc1.add(device) == device_allocator::alloc_status::success);
    CHECK(alloc2.populate_from(alloc1) == device_allocator::alloc_status::success);
    CHECK(alloc2.contains(device));
    CHECK(alloc2.populate_from(alloc1) == device_allocator::alloc_status::collision);
    CHECK(alloc2.contains(device));
    CHECK(alloc1.populate_from(alloc1) == device_allocator::alloc_status::collision);
    CHECK(alloc1.contains(device));
}

TEST_CASE("device_allocator::allocate(device_id &),allocate_bridge(device_id &)")
{
    device_id device1{};
    device_id device2{};
    device_allocator alloc{};

    CHECK(alloc.allocate(device1) == device_allocator::alloc_status::success);
    CHECK(device1.bus == 0);
    CHECK(device1.device == 0);
    CHECK(device1.func == 0);
    CHECK(device1.secondary_bus == 0);
    CHECK(alloc.contains(device1));

    CHECK(alloc.allocate(device2) == device_allocator::alloc_status::success);
    CHECK(device2.bus == 0);
    CHECK(device2.device == 1);
    CHECK(device2.func == 0);
    CHECK(device2.secondary_bus == 0);
    CHECK(alloc.contains(device2));
    CHECK(alloc.contains(device1));

    alloc.clear();

    for (int i = 0; i <= 30; ++i) {
        CHECK(alloc.allocate(device1) == device_allocator::alloc_status::success);
    }

    CHECK(alloc.allocate(device1) == device_allocator::alloc_status::bus_almost_full);

    device_id bridge{};
    CHECK(alloc.allocate_bridge(bridge) == device_allocator::alloc_status::success);
    CHECK(alloc.contains(bridge));
    CHECK(bridge.bus == 0);
    CHECK(bridge.device == 31);
    CHECK(bridge.func == 0);
    CHECK(bridge.secondary_bus == 1);

    CHECK(alloc.allocate(device1) == device_allocator::alloc_status::success);
    CHECK(alloc.contains(device1));
    CHECK(device1.bus == 1);
}

TEST_CASE("device_allocator::allocate(bus_type, device_id &)")
{
    device_id device{};
    device_allocator alloc{};

    for (int i = 0; i <= 30; ++i) {
        CHECK(alloc.allocate(0, device) == device_allocator::alloc_status::success);
        CHECK(device.bus == 0);
        CHECK(device.device == i);
    }

    device_id bridge{};
    CHECK(alloc.allocate_bridge(bridge) == device_allocator::alloc_status::success);

    CHECK(alloc.allocate(0, device) == device_allocator::alloc_status::bus_full);
    CHECK(alloc.allocate(1, device) == device_allocator::alloc_status::success);

    CHECK(device.bus == 1);

}

TEST_CASE("device_allocator::allocate_bridge(bus_type, device_id &)")
{
    device_id device{};
    device_allocator alloc{};

    for (int i = 0; i <= 30; ++i) {
        CHECK(alloc.allocate(0, device) == device_allocator::alloc_status::success);
        CHECK(device.bus == 0);
        CHECK(device.device == i);
    }

    device_id bridge1{};
    device_id bridge2{};
    CHECK(alloc.allocate_bridge(bridge1) == device_allocator::alloc_status::success);

    CHECK(alloc.allocate_bridge(0, bridge2) == device_allocator::alloc_status::bus_full);
    CHECK(alloc.allocate_bridge(1, bridge2) == device_allocator::alloc_status::success);
    CHECK(bridge1.bus == 0);
    CHECK(bridge1.secondary_bus == 1);
    CHECK(bridge2.bus == 1);
    CHECK(bridge2.secondary_bus == 2);
}

TEST_CASE("device_allocator::enumerate")
{
    std::vector<device_id> devices_in;
    std::vector<device_id> devices_out;
    device_id bridge{};
    device_allocator alloc{};

    for (size_t i = 0; i < 10; ++i) {
        device_id device{};
        CHECK(alloc.allocate(device) == device_allocator::alloc_status::success);
        devices_in.push_back(device);
    }

    CHECK(alloc.allocate_bridge(bridge) == device_allocator::alloc_status::success);
    devices_in.push_back(bridge);

    CHECK_NOTHROW(alloc.enumerate(devices_out));
    CHECK(devices_in.size() == devices_out.size());

    for (size_t i = 0; i < devices_in.size(); ++i) {
        CHECK(devices_in[i].bus == devices_out[i].bus);
        CHECK(devices_in[i].device == devices_out[i].device);
        CHECK(devices_in[i].func == devices_out[i].func);
        CHECK(devices_in[i].secondary_bus == devices_out[i].secondary_bus);
    }
}

TEST_CASE("device_allocator::populate_physical")
{
    auto ___ = cleanup();

    // Generate a few devices
    write_register(0, 0, 0, 0x00, 0x12345678);  // vendor, device
    write_register(0, 0, 0, 0x08, 0x00000000);  // class
    write_register(0, 0, 0, 0x0C, 0x00000000);  // header type

    write_register(0, 1, 0, 0x00, 0x12345678);  // vendor, device
    write_register(0, 1, 0, 0x08, 0x00000000);  // class
    write_register(0, 1, 0, 0x0C, 0x00000000);  // header type

    // A bridge
    write_register(0, 2, 0, 0x00, 0x12345678);  // vendor, device
    write_register(0, 2, 0, 0x08, 0x06040000);  // class
    write_register(0, 2, 0, 0x0C, 0x00010000);  // header type
    write_register(0, 2, 0, 0x18, 0x00000100);  // secondary bus

    write_register(1, 0, 0, 0x00, 0x12345678);  // vendor, device
    write_register(1, 0, 0, 0x08, 0x00000000);  // class
    write_register(1, 0, 0, 0x0C, 0x00000000);  // header type

    device_allocator alloc{};
    std::vector<device_id> devices;

    CHECK_NOTHROW(alloc.populate_physical());
    CHECK_NOTHROW(alloc.enumerate(devices));

    CHECK(devices.size() == 4);
    CHECK(devices[0].bus == 0);
    CHECK(devices[0].device == 0);
    CHECK(devices[0].func == 0);
    CHECK(devices[0].secondary_bus == 0);

    CHECK(devices[1].bus == 0);
    CHECK(devices[1].device == 1);
    CHECK(devices[1].func == 0);
    CHECK(devices[1].secondary_bus == 0);

    CHECK(devices[2].bus == 0);
    CHECK(devices[2].device == 2);
    CHECK(devices[2].func == 0);
    CHECK(devices[2].secondary_bus == 1);

    CHECK(devices[3].bus == 1);
    CHECK(devices[3].device == 0);
    CHECK(devices[3].func == 0);
    CHECK(devices[3].secondary_bus == 0);
}

}
}

#endif
