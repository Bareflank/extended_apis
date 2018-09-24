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

xsetbv_handler::xsetbv_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        vmcs_n::exit_reason::basic_exit_reason::xsetbv,
        ::handler_delegate_t::create<xsetbv_handler, &xsetbv_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
xsetbv_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
xsetbv_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    struct info_t info = {
        0,
        false,
        false
    };

    info.val |= ((vcpu->rax() & 0x00000000FFFFFFFF) << 0x00);
    info.val |= ((vcpu->rdx() & 0x00000000FFFFFFFF) << 0x20);

    for (const auto &d : m_handlers) {
        if (d(vcpu, info)) {
            break;
        }
    }

    if (!info.ignore_write) {
        ::intel_x64::xcr0::set(info.val);
    }

    if (!info.ignore_advance) {
        return advance(vcpu);
    }

    return true;
}

}
