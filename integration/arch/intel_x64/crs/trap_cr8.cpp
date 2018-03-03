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
        this->enable_cr_trapping();

        if (!ndebug) {
            crs()->enable_log();
        }

        crs()->enable_rdcr8_trapping();
        crs()->enable_wrcr8_trapping();

        crs()->add_rdcr8_handler(
            crs::rdcr8_handler_delegate_t::create<vcpu, &vcpu::test_rdcr8_handler>(this)
        );

        crs()->add_wrcr8_handler(
            crs::wrcr8_handler_delegate_t::create<vcpu, &vcpu::test_wrcr8_handler>(this)
        );

        m_tpr_shadow = ::intel_x64::cr8::get();
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Read CR8
    ///
    /// @expects
    /// @ensures
    ///
    bool
    test_rdcr8_handler(
        gsl::not_null<vmcs_t *> vmcs, crs::info_t &info)
    {
        bfignored(vmcs);

        info.val = m_tpr_shadow;
        return true;
    }

    /// Write CR8
    ///
    /// @expects
    /// @ensures
    ///
    bool
    test_wrcr8_handler(
        gsl::not_null<vmcs_t *> vmcs, crs::info_t &info)
    {
        bfignored(vmcs);

        m_tpr_shadow = info.val;
        return true;
    }

private:

    uint64_t m_tpr_shadow;
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
