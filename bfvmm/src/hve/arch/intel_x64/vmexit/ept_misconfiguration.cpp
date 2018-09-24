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

ept_misconfiguration_handler::ept_misconfiguration_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::ept_misconfiguration,
        ::handler_delegate_t::create<ept_misconfiguration_handler, &ept_misconfiguration_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
ept_misconfiguration_handler::add_handler(const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_misconfiguration_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    struct info_t info = {
        vmcs_n::guest_linear_address::get(),
        vmcs_n::guest_physical_address::get(),
        false
    };

    for (const auto &d : m_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return advance(vcpu);
            }

            return true;
        }
    }

    throw std::runtime_error(
        "ept_misconfiguration_handler::handle: unhandled ept misconfiguration"
    );
}

}
