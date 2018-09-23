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
#include <bfvmm/memory_manager/arch/x64/unique_map.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

bfn::once_flag flag;
ept::mmap g_guest_map;

alignas(0x1000) std::array<uint8_t, 0x1000> buffer1;
alignas(0x1000) std::array<uint8_t, 0x1000> buffer2;

void
test_hlt_delegate(bfobject *obj)
{
    bfignored(obj);

    ::x64::cpuid::get(
        42, 0, 0, 0
    );

    bfdebug_ndec(0, "A: buffer1.at(0)", buffer1.at(0));
    bfdebug_ndec(0, "A: buffer2.at(0)", buffer2.at(0));
}

class vcpu : public eapis::intel_x64::vcpu
{
public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        eapis()->add_cpuid_handler(
            42, cpuid_handler::handler_delegate_t::create<vcpu, &vcpu::test_cpuid_handler>(this)
        );

        this->add_hlt_delegate(
            hlt_delegate_t::create<test_hlt_delegate>()
        );

        for (auto &elem : buffer1) {
            elem = 42;
        }

        for (auto &elem : buffer2) {
            elem = 43;
        }

        bfdebug_ndec(0, "B: buffer1.at(0)", buffer1.at(0));
        bfdebug_ndec(0, "B: buffer2.at(0)", buffer2.at(0));
    }

    bool
    test_cpuid_handler(
        gsl::not_null<vmcs_t *> vmcs, cpuid_handler::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        bfn::call_once(flag, [&] {
            auto cr3 = intel_x64::vmcs::guest_cr3::get();
            auto gpa1 = bfvmm::x64::virt_to_phys_with_cr3(buffer1.data(), cr3);
            auto gpa2 = bfvmm::x64::virt_to_phys_with_cr3(buffer2.data(), cr3);

            auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
            auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
            auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

            ept::identity_map(
                g_guest_map,
                MAX_PHYS_ADDR
            );

            ept::identity_map_convert_2m_to_4k(
                g_guest_map,
                gpa1_2m
            );

            auto &pte = g_guest_map.entry(gpa1_4k);
            ::intel_x64::ept::pt::entry::phys_addr::set(pte, gpa2_4k);
        });

        eapis()->set_eptp(g_guest_map);

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
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
