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

// Same thing.... search for the headers in cpp files. I would go through all
// of the source files and make sure this is fixed.

namespace eapis
{
namespace intel_x64
{

class vcpu : public bfvmm::intel_x64::vcpu
{
public:
    vcpu(vcpuid::type id) :
        bfvmm::intel_x64::vcpu{id}
    {
        m_vmcs_clean_me_up = std::make_unique<eapis::intel_x64::vmcs>();
        m_exit_handler_clean_me_up = std::make_unique<eapis::intel_x64::exit_handler>(vmcs());
    }

    ~vcpu() override
    { }

private:

    // When the cleanup is done, the VMCS and exit handler will be gone. Instead,
    // each API will have it's own class, and all of the setup, APIs, and handlers
    // will be in that class, created here, and registered here.

    std::unique_ptr<eapis::intel_x64::vmcs> m_vmcs_clean_me_up;
    std::unique_ptr<eapis::intel_x64::exit_handler> m_exit_handler_clean_me_up;
};

} // namespace intel_x64
} // namespace eapis

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    bfdebug_info(0, "eapis: make_vcpu");
    return std::make_unique<eapis::intel_x64::vcpu>(vcpuid);
}

}
