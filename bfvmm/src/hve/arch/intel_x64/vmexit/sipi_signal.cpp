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

#include <bfdebug.h>
#include <hve/arch/intel_x64/apis.h>

namespace eapis
{
namespace intel_x64
{

sipi_signal_handler::sipi_signal_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<eapis_vcpu_global_state_t *> eapis_vcpu_global_state)
{
    using namespace vmcs_n;
    bfignored(eapis_vcpu_global_state);

    apis->add_handler(
        exit_reason::basic_exit_reason::sipi,
        ::handler_delegate_t::create<sipi_signal_handler, &sipi_signal_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
sipi_signal_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{

    using namespace vmcs_n::guest_activity_state;
    using namespace vmcs_n::vm_entry_controls;
    bfignored(vmcs);

    // .........................................................................
    // Ignore SIPI - SIPI
    // .........................................................................

    // The Intel spec states that more than one SIPI should be sent
    // to each AP in the event that the first AP is ignored. The problem
    // with this approach is that it is possible for the exit handler to
    // see both SIPIs (i.e. the second sipi is not actually dropped by
    // the CPU). If this happens, we need to emulate this drop our selves
    //

    if (vmcs_n::guest_activity_state::get() == active) {
        return true;
    }


    // .........................................................................
    // SIPI
    // .........................................................................

    // This is where we actually execute the SIPI logic. Most of the code here
    // overwrites some of the logic in the INIT code above, but we wanted this
    // to be easy to read and self documenting, and the extra time it takes
    // to redo some of these registers is not important.
    //
    // When a SIPI is received, the first instruction executed by the
    // guest is 0x000VV000, with VV being the vector number supplied
    // in the SIPI (hence why the first instruction needs to be page
    // aligned).
    //
    // The segment selector is VV << 8 because we don't need to shift
    // by a full 12 bits since the first 4 bits are the RPL and TI bits.
    //

    uint64_t vector_cs_selector =
        vmcs_n::exit_qualification::sipi::vector::get() << 8;

    uint64_t vector_cs_base =
        vmcs_n::exit_qualification::sipi::vector::get() << 12;

    vmcs_n::guest_cs_selector::set(vector_cs_selector);
    vmcs_n::guest_cs_base::set(vector_cs_base);
    vmcs_n::guest_cs_limit::set(0xFFFF);
    vmcs_n::guest_cs_access_rights::set(0x9B);

    vmcs->save_state()->rip = 0;

    vmcs_n::guest_activity_state::set(
        vmcs_n::guest_activity_state::active
    );

    // .........................................................................
    // Done
    // .........................................................................

    return true;
}

}
}
