//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Jonathan Cohen Scaly <scalys7@gmail.com>
// Author: Rian Quinn           <quinnr@ainfosec.com>
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

#include <arch/intel_x64/crs.h>
#include <exit_handler/exit_handler_intel_x64_eapis.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;
using namespace exit_qualification::control_register_access;

void
exit_handler_intel_x64_eapis::handle_exit__ctl_reg_access()
{
    auto type = access_type::get();
    auto index = general_purpose_register::get();

    switch (control_register_number::get()) {

        case 0: {
            auto ret = this->cr0_ld_callback(this->get_gpr(index));
            guest_cr0::set(ret);

            this->advance_and_resume();
            return;
        }

        case 3: {
            switch (type) {

                case access_type::mov_to_cr: {
                    auto ret = this->cr3_ld_callback(this->get_gpr(index));
                    guest_cr3::set(ret);

                    this->advance_and_resume();
                    return;
                }

                case access_type::mov_from_cr: {
                    auto ret = this->cr3_st_callback(guest_cr3::get());
                    this->set_gpr(index, ret);

                    this->advance_and_resume();
                    return;
                }
            }
        }

        case 4: {
            auto ret = this->cr4_ld_callback(this->get_gpr(index));
            guest_cr4::set(ret);

            this->advance_and_resume();
            return;
        }

        case 8: {
            switch (type) {

                case access_type::mov_to_cr: {
                    auto ret = this->cr8_ld_callback(this->get_gpr(index));
                    cr8::set(ret);

                    this->advance_and_resume();
                    return;
                }

                case access_type::mov_from_cr: {
                    auto ret = this->cr8_st_callback(cr8::get());
                    this->set_gpr(index, ret);

                    this->advance_and_resume();
                    return;
                }
            }
        }

        default: {
            throw std::runtime_error("invalid control register number");
        }
    }
}

exit_handler_intel_x64_eapis::cr0_value_type
exit_handler_intel_x64_eapis::cr0_ld_callback(cr0_value_type val)
{ return val; }

exit_handler_intel_x64_eapis::cr3_value_type
exit_handler_intel_x64_eapis::cr3_ld_callback(cr3_value_type val)
{ return val; }

exit_handler_intel_x64_eapis::cr3_value_type
exit_handler_intel_x64_eapis::cr3_st_callback(cr3_value_type val)
{ return val; }

exit_handler_intel_x64_eapis::cr4_value_type
exit_handler_intel_x64_eapis::cr4_ld_callback(cr4_value_type val)
{ return val; }

exit_handler_intel_x64_eapis::cr8_value_type
exit_handler_intel_x64_eapis::cr8_ld_callback(cr8_value_type val)
{
    m_tpr_shadow = val;
    return val;
}

exit_handler_intel_x64_eapis::cr8_value_type
exit_handler_intel_x64_eapis::cr8_st_callback(cr8_value_type val)
{
    bfignored(val);
    return m_tpr_shadow;
}
