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

#include <bfcallonce.h>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

bfn::once_flag flag;
ept::mmap g_guest_map;

alignas(0x200000) std::array<uint8_t, 0x200000> buffer;

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);
    buffer.at(0) = 42;
}

class vcpu : public eapis::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        bfn::call_once(flag, [&] {
            ept::identity_map(
                g_guest_map,
                MAX_PHYS_ADDR
            );
        });

        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        eapis()->add_ept_write_violation_handler(
            ept_violation_handler::handler_delegate_t::create<vcpu, &vcpu::test_write_violation_handler>(this)
        );

        auto &pte =
            g_guest_map.entry(
                g_mm->virtptr_to_physint(buffer.data())
            );

        ::intel_x64::ept::pd::entry::read_access::disable(pte);
        ::intel_x64::ept::pd::entry::write_access::disable(pte);
        ::intel_x64::ept::pd::entry::execute_access::disable(pte);

        eapis()->set_eptp(g_guest_map);
    }

    bool
    test_write_violation_handler(
        gsl::not_null<vmcs_t *> vmcs, ept_violation_handler::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        bfdebug_info(0, "disabling EPT");
        eapis()->disable_ept();

        return true;
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
