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

#include <exit_handler/exit_handler_intel_x64_eapis.h>

#include <arch/intel_x64/vmcs/32bit_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_guest_state_fields.h>
#include <arch/intel_x64/crs.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;
using namespace exit_qualification::control_register_access;

exit_handler_intel_x64_eapis::gpr_value_type
exit_handler_intel_x64_eapis::get_gpr(gpr_index_type index)
{
    switch (index)
    {
        case general_purpose_register::rax:
            return m_state_save->rax;

        case general_purpose_register::rbx:
            return m_state_save->rbx;

        case general_purpose_register::rcx:
            return m_state_save->rcx;

        case general_purpose_register::rdx:
            return m_state_save->rdx;

        case general_purpose_register::rsp:
            return m_state_save->rsp;

        case general_purpose_register::rbp:
            return m_state_save->rbp;

        case general_purpose_register::rsi:
            return m_state_save->rsi;

        case general_purpose_register::rdi:
            return m_state_save->rdi;

        case general_purpose_register::r8:
            return m_state_save->r08;

        case general_purpose_register::r9:
            return m_state_save->r09;

        case general_purpose_register::r10:
            return m_state_save->r10;

        case general_purpose_register::r11:
            return m_state_save->r11;

        case general_purpose_register::r12:
            return m_state_save->r12;

        case general_purpose_register::r13:
            return m_state_save->r13;

        case general_purpose_register::r14:
            return m_state_save->r14;

        case general_purpose_register::r15:
            return m_state_save->r15;
    }

    throw std::runtime_error("unknown index");
}


void
exit_handler_intel_x64_eapis::set_gpr(
    gpr_index_type index, gpr_value_type val)
{
    switch (index)
    {
        case general_purpose_register::rax:
            m_state_save->rax = val;
            return;

        case general_purpose_register::rbx:
            m_state_save->rbx = val;
            return;

        case general_purpose_register::rcx:
            m_state_save->rcx = val;
            return;

        case general_purpose_register::rdx:
            m_state_save->rdx = val;
            return;

        case general_purpose_register::rsp:
            m_state_save->rsp = val;
            return;

        case general_purpose_register::rbp:
            m_state_save->rbp = val;
            return;

        case general_purpose_register::rsi:
            m_state_save->rsi = val;
            return;

        case general_purpose_register::rdi:
            m_state_save->rdi = val;
            return;

        case general_purpose_register::r8:
            m_state_save->r08 = val;
            return;

        case general_purpose_register::r9:
            m_state_save->r09 = val;
            return;

        case general_purpose_register::r10:
            m_state_save->r10 = val;
            return;

        case general_purpose_register::r11:
            m_state_save->r11 = val;
            return;

        case general_purpose_register::r12:
            m_state_save->r12 = val;
            return;

        case general_purpose_register::r13:
            m_state_save->r13 = val;
            return;

        case general_purpose_register::r14:
            m_state_save->r14 = val;
            return;

        case general_purpose_register::r15:
            m_state_save->r15 = val;
            return;
    }

    throw std::runtime_error("unknown index");
}

void
exit_handler_intel_x64_eapis::handle_exit__ctl_reg_access()
{
    auto type = access_type::get();
    auto index = general_purpose_register::get();

    switch (control_register_number::get())
    {
        case 0:
        {
            auto ret = this->cr0_ld_callback(this->get_gpr(index));
            guest_cr0::set(ret);

            this->advance_and_resume();
            return;
        }

        case 3:
        {
            switch (type)
            {
                case access_type::mov_to_cr:
                {
                    auto ret = this->cr3_ld_callback(this->get_gpr(index));
                    guest_cr3::set(ret);

                    this->advance_and_resume();
                    return;
                }

                case access_type::mov_from_cr:
                {
                    auto ret = this->cr3_st_callback(guest_cr3::get());
                    this->set_gpr(index, ret);

                    this->advance_and_resume();
                    return;
                }
            }
        }

        case 4:
        {
            auto ret = this->cr4_ld_callback(this->get_gpr(index));
            guest_cr4::set(ret);

            this->advance_and_resume();
            return;
        }

        case 8:
        {
            switch (type)
            {
                case access_type::mov_to_cr:
                {
                    auto ret = this->cr8_ld_callback(this->get_gpr(index));
                    cr8::set(ret);

                    this->advance_and_resume();
                    return;
                }

                case access_type::mov_from_cr:
                {
                    auto ret = this->cr8_st_callback(cr8::get());
                    this->set_gpr(index, ret);

                    this->advance_and_resume();
                    return;
                }
            }
        }

        default:
        {
            bferror_info(0, "unknown control register access");
            break;
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
{ return val; }

exit_handler_intel_x64_eapis::cr8_value_type
exit_handler_intel_x64_eapis::cr8_st_callback(cr8_value_type val)
{ return val; }
