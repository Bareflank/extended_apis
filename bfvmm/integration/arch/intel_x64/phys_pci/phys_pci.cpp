//
// Bareflank Extended APIs
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

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/vcpu/arch/intel_x64/vcpu.h>
#include <eapis/hve/phys_pci.h>
#include <vector>

using namespace eapis;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public eapis::intel_x64::vcpu
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu()
    {
        std::vector<pci::phys_pci> devices;
        pci::phys_pci::enumerate(devices);

        if (id() == 0) {
            for (auto &device : devices) {
                bfdebug_brk31(0);
                bfdebug_nhex(0, "Bus", device.bus());
                bfdebug_nhex(0, "Device", device.device());
                bfdebug_nhex(0, "Function", device.func());
                bfdebug_nhex(0, "Vendor ID", device.vendor_id());
                bfdebug_nhex(0, "Device ID", device.device_id());
            }
        }
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
