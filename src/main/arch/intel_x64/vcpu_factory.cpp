//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <bfdebug.h>
#include <bftypes.h>
#include <bfdelegate.h>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <bfvmm/vcpu/arch/intel_x64/vcpu.h>

#include <hve/arch/intel_x64/exit_handler/rdmsr.h>
#include <vic/arch/intel_x64/isr.h>

namespace eapis
{
namespace intel_x64
{

static const auto msr_3b = 0x3b;

bool handle_msr_3b(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs)
{
    return false;
}

class vcpu : public bfvmm::intel_x64::vcpu
{
public:
    vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        using vmcs_t = bfvmm::intel_x64::vmcs;
        using hdlr_t = delegate<bool(gsl::not_null<vmcs_t *>)>;

        auto exit_hdlr = this->exit_handler();

        m_rdmsr = std::make_unique<eapis::intel_x64::rdmsr>();
        m_rdmsr->set(msr_3b, hdlr_t::create<handle_msr_3b>());
        m_rdmsr->enable(exit_hdlr);

        isr::init_vmm_idt(exit_hdlr);
        //enable_interrupts();
    }

    ~vcpu() override
    {
    }

private:
    std::unique_ptr<eapis::intel_x64::rdmsr> m_rdmsr;
};

} // namespace intel_x64
} // namespace eapis

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<eapis::intel_x64::vcpu>(vcpuid);
}

} // namespace bfvmm
