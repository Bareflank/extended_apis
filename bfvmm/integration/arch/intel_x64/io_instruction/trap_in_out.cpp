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

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
test_handler(
    gsl::not_null<vmcs_t *> vmcs, io_instruction::info_t &info)
{ bfignored(vmcs); bfignored(info); return true; }

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
    vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        hve()->add_io_instruction_handler(
            0xCF8,
            io_instruction::handler_delegate_t::create<test_handler>(),
            io_instruction::handler_delegate_t::create<test_handler>()
        );

        hve()->add_io_instruction_handler(
            0xCFC,
            io_instruction::handler_delegate_t::create<test_handler>(),
            io_instruction::handler_delegate_t::create<test_handler>()
        );

        hve()->io_instruction()->enable_log();
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu()
    {
        uint32_t addr = 0x80000800;
        uint32_t data[10] = {};

        ::x64::portio::outd(0xCF8, 0x80000000);
        bfdebug_nhex(0, "PCI Configuration Space (addr)", ::x64::portio::ind(0xCF8));
        bfdebug_nhex(0, "PCI Configuration Space (data)", ::x64::portio::ind(0xCFC));

        ::x64::portio::outsd(0xCF8, &addr);
        ::x64::portio::insd(0xCFC, data);
        bfdebug_nhex(0, "PCI Configuration Space (addr)", ::x64::portio::ind(0xCF8));
        bfdebug_nhex(0, "PCI Configuration Space (data)", data[0]);
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
