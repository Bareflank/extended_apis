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

#include "../../../../../include/hve/arch/intel_x64/exit_handler/exit_handler.h"

#include <arch/intel_x64/vmcs/32bit_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_guest_state_fields.h>
#include <arch/intel_x64/crs.h>

namespace cr_access = ::intel_x64::vmcs::exit_qualification::control_register_access;
namespace gpr = cr_access::general_purpose_register;
using ehlr_eapis = eapis::intel_x64::exit_handler;

ehlr_eapis::gpr_value_type
ehlr_eapis::get_gpr(gpr_index_type index)
{
    switch (index) {
        case gpr::rax:
            return m_vmcs->save_state()->rax;

        case gpr::rbx:
            return m_vmcs->save_state()->rbx;

        case gpr::rcx:
            return m_vmcs->save_state()->rcx;

        case gpr::rdx:
            return m_vmcs->save_state()->rdx;

        case gpr::rsp:
            return m_vmcs->save_state()->rsp;

        case gpr::rbp:
            return m_vmcs->save_state()->rbp;

        case gpr::rsi:
            return m_vmcs->save_state()->rsi;

        case gpr::rdi:
            return m_vmcs->save_state()->rdi;

        case gpr::r8:
            return m_vmcs->save_state()->r08;

        case gpr::r9:
            return m_vmcs->save_state()->r09;

        case gpr::r10:
            return m_vmcs->save_state()->r10;

        case gpr::r11:
            return m_vmcs->save_state()->r11;

        case gpr::r12:
            return m_vmcs->save_state()->r12;

        case gpr::r13:
            return m_vmcs->save_state()->r13;

        case gpr::r14:
            return m_vmcs->save_state()->r14;

        case gpr::r15:
            return m_vmcs->save_state()->r15;
    }

    throw std::runtime_error("unknown index");
}


void
ehlr_eapis::set_gpr(
    gpr_index_type index, gpr_value_type val)
{
    switch (index) {
        case gpr::rax:
            m_vmcs->save_state()->rax = val;
            return;

        case gpr::rbx:
            m_vmcs->save_state()->rbx = val;
            return;

        case gpr::rcx:
            m_vmcs->save_state()->rcx = val;
            return;

        case gpr::rdx:
            m_vmcs->save_state()->rdx = val;
            return;

        case gpr::rsp:
            m_vmcs->save_state()->rsp = val;
            return;

        case gpr::rbp:
            m_vmcs->save_state()->rbp = val;
            return;

        case gpr::rsi:
            m_vmcs->save_state()->rsi = val;
            return;

        case gpr::rdi:
            m_vmcs->save_state()->rdi = val;
            return;

        case gpr::r8:
            m_vmcs->save_state()->r08 = val;
            return;

        case gpr::r9:
            m_vmcs->save_state()->r09 = val;
            return;

        case gpr::r10:
            m_vmcs->save_state()->r10 = val;
            return;

        case gpr::r11:
            m_vmcs->save_state()->r11 = val;
            return;

        case gpr::r12:
            m_vmcs->save_state()->r12 = val;
            return;

        case gpr::r13:
            m_vmcs->save_state()->r13 = val;
            return;

        case gpr::r14:
            m_vmcs->save_state()->r14 = val;
            return;

        case gpr::r15:
            m_vmcs->save_state()->r15 = val;
            return;
    }

    throw std::runtime_error("unknown index");
}

void
ehlr_eapis::handle_exit__ctl_reg_access()
{
    auto type = cr_access::access_type::get();
    auto index = gpr::get();

    switch (cr_access::control_register_number::get()) {
        case 0: {
            auto ret = this->cr0_ld_callback(this->get_gpr(index));
            ::intel_x64::vmcs::guest_cr0::set(ret);

//            this->advance_and_resume();
            return;
        }

        case 3: {
            switch (type) {
                case cr_access::access_type::mov_to_cr: {
                    auto ret = this->cr3_ld_callback(this->get_gpr(index));
                    ::intel_x64::vmcs::guest_cr3::set(ret);

//                    this->advance_and_resume();
                    return;
                }

                case cr_access::access_type::mov_from_cr: {
                    auto ret = this->cr3_st_callback(::intel_x64::vmcs::guest_cr3::get());
                    this->set_gpr(index, ret);

//                    this->advance_and_resume();
                    return;
                }
            }
            return;
        }

        case 4: {
            auto ret = this->cr4_ld_callback(this->get_gpr(index));
            ::intel_x64::vmcs::guest_cr4::set(ret);

//            this->advance_and_resume();
            return;
        }

        case 8: {
            switch (type) {
                case cr_access::access_type::mov_to_cr: {
                    auto ret = this->cr8_ld_callback(this->get_gpr(index));
                    ::intel_x64::cr8::set(ret);

//                    this->advance_and_resume();
                    return;
                }

                case cr_access::access_type::mov_from_cr: {
                    auto ret = this->cr8_st_callback(::intel_x64::cr8::get());
                    this->set_gpr(index, ret);

//                    this->advance_and_resume();
                    return;
                }
            }
            return;
        }

        default: {
            bferror_info(0, "unknown control register access");
            break;
        }
    }
}

ehlr_eapis::cr0_value_type
ehlr_eapis::cr0_ld_callback(cr0_value_type val)
{ return val; }

ehlr_eapis::cr3_value_type
ehlr_eapis::cr3_ld_callback(cr3_value_type val)
{ return val; }

ehlr_eapis::cr3_value_type
ehlr_eapis::cr3_st_callback(cr3_value_type val)
{ return val; }

ehlr_eapis::cr4_value_type
ehlr_eapis::cr4_ld_callback(cr4_value_type val)
{ return val; }

ehlr_eapis::cr8_value_type
ehlr_eapis::cr8_ld_callback(cr8_value_type val)
{ return val; }

ehlr_eapis::cr8_value_type
ehlr_eapis::cr8_st_callback(cr8_value_type val)
{ return val; }
