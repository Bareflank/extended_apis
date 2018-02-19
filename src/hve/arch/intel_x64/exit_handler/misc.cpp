//
// Bareflank Extended APIs
//
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

#include <hve/arch/intel_x64/exit_handler/misc.h>

namespace eapis
{
namespace intel_x64
{

using vmcs_t = bfvmm::intel_x64::vmcs;

::intel_x64::vmcs::value_type
read_gpr(
    gsl::not_null<vmcs_t *> vmcs,
    ::intel_x64::vmcs::value_type index)
{
    auto state = vmcs->save_state();

    switch (index) {
        case gpr::rax:
            return state->rax;

        case gpr::rbx:
            return state->rbx;

        case gpr::rcx:
            return state->rcx;

        case gpr::rdx:
            return state->rdx;

        case gpr::rsp:
            return state->rsp;

        case gpr::rbp:
            return state->rbp;

        case gpr::rsi:
            return state->rsi;

        case gpr::rdi:
            return state->rdi;

        case gpr::r8:
            return state->r08;

        case gpr::r9:
            return state->r09;

        case gpr::r10:
            return state->r10;

        case gpr::r11:
            return state->r11;

        case gpr::r12:
            return state->r12;

        case gpr::r13:
            return state->r13;

        case gpr::r14:
            return state->r14;

        case gpr::r15:
            return state->r15;
    }

    throw std::runtime_error("unknown index");
}

void
write_gpr(
    gsl::not_null<vmcs_t *> vmcs,
    ::intel_x64::vmcs::value_type index,
    ::intel_x64::vmcs::value_type val)
{
    auto state = vmcs->save_state();

    switch (index) {
        case gpr::rax:
            state->rax = val;
            return;

        case gpr::rbx:
            state->rbx = val;
            return;

        case gpr::rcx:
            state->rcx = val;
            return;

        case gpr::rdx:
            state->rdx = val;
            return;

        case gpr::rsp:
            state->rsp = val;
            return;

        case gpr::rbp:
            state->rbp = val;
            return;

        case gpr::rsi:
            state->rsi = val;
            return;

        case gpr::rdi:
            state->rdi = val;
            return;

        case gpr::r8:
            state->r08 = val;
            return;

        case gpr::r9:
            state->r09 = val;
            return;

        case gpr::r10:
            state->r10 = val;
            return;

        case gpr::r11:
            state->r11 = val;
            return;

        case gpr::r12:
            state->r12 = val;
            return;

        case gpr::r13:
            state->r13 = val;
            return;

        case gpr::r14:
            state->r14 = val;
            return;

        case gpr::r15:
            state->r15 = val;
            return;
    }

    throw std::runtime_error("unknown index");
}

} // namespace intel_x64
} // namespace eapis
