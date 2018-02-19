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

#include <hve/arch/intel_x64/exit_handler/wrmsr.h>

namespace eapis
{
namespace intel_x64
{

void
wrmsr::enable(gsl::not_null<exit_hdlr_t *> exit_hdlr)
{
    exit_hdlr->add_dispatch_delegate(
        s_reason,
        hdlr_t::create<wrmsr_t, &wrmsr_t::handle>(this)
    );
}

void
wrmsr::set_default(hdlr_t &&hdlr)
{
    m_def_hdlr = hdlr;
}

void
wrmsr::set(const addr_t addr, hdlr_t &&hdlr)
{
    if (m_handlers.count(addr) > 0) {
        return;
    }

    m_handlers[addr] = hdlr;
}

void
wrmsr::clear_default()
{
    set_default(hdlr_t::create<nullptr>());
    return;
}

void
wrmsr::clear(const addr_t addr)
{
    if (m_handlers.count(addr) == 0) {
        return;
    }

    m_handlers.erase(addr);
    return;
}

bool
wrmsr::handle(gsl::not_null<vmcs_t *> vmcs)
{
    const auto addr = vmcs->save_state()->rcx;
    if (m_handlers.count(addr) == 0) {
        if (m_def_hdlr.is_valid()) {
             return m_def_hdlr(vmcs);
        }

        return false;
    }

    return m_handlers[addr](vmcs);
}

} // namespace intel_x64
} // namespace eapis
