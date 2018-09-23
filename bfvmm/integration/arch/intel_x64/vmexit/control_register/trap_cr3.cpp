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
#include <eapis/hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

auto rdcr3_called = false;
auto wrcr3_called = false;

bool
test_rdcr3_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    rdcr3_called = true;
    return false;
}

bool
test_wrcr3_handler(
    gsl::not_null<vmcs_t *> vmcs, control_register_handler::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    wrcr3_called = true;
    return false;
}

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    auto cr3 = ::intel_x64::cr3::get();
    ::intel_x64::cr3::set(cr3);

    if (rdcr3_called && wrcr3_called) {
        bfdebug_pass(0, "test");
    }
}

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public eapis::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        eapis()->add_rdcr3_handler(
            control_register_handler::handler_delegate_t::create<test_rdcr3_handler>()
        );

        eapis()->add_wrcr3_handler(
            control_register_handler::handler_delegate_t::create<test_wrcr3_handler>()
        );

        eapis()->control_register()->enable_log();
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
