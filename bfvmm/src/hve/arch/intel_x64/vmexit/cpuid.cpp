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

#include <hve/arch/intel_x64/vcpu.h>

namespace eapis::intel_x64
{

static bool
handle_cpuid_feature_information(
    gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Currently, we do not support nested virtualization. As a result,
    // the EAPIs adds a default handler to disable support for VMXE here.
    //

    info.rcx =
        clear_bit(
            info.rcx, ::intel_x64::cpuid::feature_information::ecx::vmx::from
        );

    return true;
}

cpuid_handler::cpuid_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::cpuid,
        ::handler_delegate_t::create<cpuid_handler, &cpuid_handler::handle>(this)
    );

    this->add_handler(
        ::intel_x64::cpuid::feature_information::addr,
        cpuid_handler::handler_delegate_t::create<handle_cpuid_feature_information>()
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
cpuid_handler::add_handler(
    leaf_t leaf, const handler_delegate_t &d)
{ m_handlers[leaf].push_front(d); }

void
cpuid_handler::emulate(leaf_t leaf)
{ m_emulate[leaf] = true; }

void
cpuid_handler::set_default_handler(
    const ::handler_delegate_t &d)
{ m_default_handler = d; }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
cpuid_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    const auto &hdlrs =
        m_handlers.find(vcpu->rax());

    if (hdlrs != m_handlers.end()) {

        struct info_t info = {
            0, 0, 0, 0, false, false
        };

        if (!m_emulate[vcpu->rax()]) {
            auto [rax, rbx, rcx, rdx] =
                ::x64::cpuid::get(
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
                    gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
                );

            info.rax = rax;
            info.rbx = rbx;
            info.rcx = rcx;
            info.rdx = rdx;
        }

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_write) {
                    vcpu->set_rax(set_bits(vcpu->rax(), 0x00000000FFFFFFFFULL, info.rax));
                    vcpu->set_rbx(set_bits(vcpu->rbx(), 0x00000000FFFFFFFFULL, info.rbx));
                    vcpu->set_rcx(set_bits(vcpu->rcx(), 0x00000000FFFFFFFFULL, info.rcx));
                    vcpu->set_rdx(set_bits(vcpu->rdx(), 0x00000000FFFFFFFFULL, info.rdx));
                }

                if (!info.ignore_advance) {
                    return advance(vcpu);
                }

                return true;
            }
        }
    }

    if (m_default_handler.is_valid()) {
        return m_default_handler(vcpu);
    }

    return false;
}

}
