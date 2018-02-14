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

#include "../../../../include/hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"

namespace eapis
{
namespace intel_x64
{

class vcpu : public bfvmm::vcpu
{
public:
    using run_dlg_t = bfvmm::vcpu::run_delegate_t;

    vcpu(vcpuid::type id) : bfvmm::vcpu{id}
    {
        if (this->is_host_vm_vcpu()) {
            m_vmx = std::make_unique<bfvmm::intel_x64::vmx>();
        }

        m_vmcs = std::make_unique<eapis::intel_x64::vmcs>(id);
        m_exit_hdlr = std::make_unique<eapis::intel_x64::exit_handler>(m_vmcs.get());

        this->add_run_delegate(
            run_dlg_t::create<eapis::intel_x64::vcpu, &eapis::intel_x64::vcpu::run>(this)
        );
    }

    ~vcpu() override
    {
        if (this->is_host_vm_vcpu()) {
            m_vmx.reset();
        }

        m_vmcs.reset();
        m_exit_hdlr.reset();
    }

    void run(bfobject *obj)
    {
        bfignored(obj);

        m_vmcs->load();
        m_vmcs->launch();
    }

    auto vmcs() const noexcept
    { return m_vmcs.get(); }

    auto exit_hdlr() const noexcept
    { return m_exit_hdlr.get(); }

private:

    std::unique_ptr<bfvmm::intel_x64::vmx> m_vmx;
    std::unique_ptr<eapis::intel_x64::vmcs> m_vmcs;
    std::unique_ptr<eapis::intel_x64::exit_handler> m_exit_hdlr;
};

} // namespace intel_x64
} // namespace eapis

namespace bfvmm
{

WEAK_SYM std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    bfdebug_info(0, "eapis: make_vcpu");
    return std::make_unique<eapis::intel_x64::vcpu>(vcpuid);
}

}
