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

init_signal_handler::init_signal_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::init_signal,
        ::handler_delegate_t::create<init_signal_handler, &init_signal_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
init_signal_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    // NOTE:
    //
    // Linux has a default setting for new CPUs that disables the delay
    // between INIT/SIPI. As a result, this handler may never be called
    // which in turn will prevent the SIPI handler from ever getting
    // called. To prevent this issue, use the cpu_init_udelay kernel param
    // in Linux to turn the delay back on. The default is 10000 which
    // seems to work.
    //
    // For the same reason above, do not add any code to this routine.
    // The INIT/SIPI process is really fragile and as a result, all INIT
    // logic should actually be placed in the SIPI handler as that handler
    // can take as long as it needs to. INIT has to return ASAP.
    //

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::wait_for_sipi
    );

    return true;
}

}
