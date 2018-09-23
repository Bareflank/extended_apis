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

#include <list>
#include <bfvmm/memory_manager/object_allocator.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

bfn::once_flag flag;
ept::mmap g_guest_map;

class vcpu : public eapis::intel_x64::vcpu
{
    std::list<uint64_t, object_allocator<uint64_t, 1>> m_vectors;

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

        eapis()->add_wrmsr_handler(
            ::intel_x64::msrs::ia32_apic_base::addr,
            wrmsr_handler::handler_delegate_t::create<vcpu, &vcpu::ia32_apic_base__wrmsr_handler>(this)
        );

        exit_handler()->add_handler(
            vmcs_n::exit_reason::basic_exit_reason::vmcall,
            ::handler_delegate_t::create<vcpu, &vcpu::vmcall_handler>(this)
        );

        eapis()->set_eptp(g_guest_map);
    }

    bool
    vmcall_handler(
        gsl::not_null<vmcs_t *> vmcs)
    {
        guard_exceptions([&] {
            vmcs->save_state()->rax = 0x1;
        });

        return advance(vmcs);
    }

    bool
    external_interrupt_handler(
        gsl::not_null<vmcs_t *> vmcs, external_interrupt_handler::info_t &info)
    {
        bfignored(vmcs);

        if (eapis()->is_interrupt_window_open()) {
            eapis()->inject_external_interrupt(info.vector);
        }
        else {
            eapis()->trap_on_next_interrupt_window();
            m_vectors.push_back(info.vector);
        }

        return true;
    }

    bool
    interrupt_window_handler(
        gsl::not_null<vmcs_t *> vmcs, interrupt_window_handler::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        eapis()->inject_external_interrupt(m_vectors.back());
        m_vectors.pop_back();

        if (!m_vectors.empty()) {
            info.ignore_disable = true;
        }

        return true;
    }

    bool
    ia32_apic_base__wrmsr_handler(
        gsl::not_null<vmcs_t *> vmcs, wrmsr_handler::info_t &info)
    {
        bfignored(vmcs);

        if (::intel_x64::msrs::ia32_apic_base::extd::is_enabled(info.val)) {
            eapis()->add_external_interrupt_handler(
                external_interrupt_handler::handler_delegate_t::create<vcpu, &vcpu::external_interrupt_handler>(this)
            );

            eapis()->add_interrupt_window_handler(
                interrupt_window_handler::handler_delegate_t::create<vcpu, &vcpu::interrupt_window_handler>(this)
            );
        }
        else {
            bferror_info(0, "local xAPIC mode is not supported");
        }

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
