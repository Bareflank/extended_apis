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

#include <hve/arch/intel_x64/exit_handler/cr_access.h>

namespace eapis
{
namespace intel_x64
{

void
cr_access::enable(gsl::not_null<exit_hdlr_t *> exit_hdlr)
{
    exit_hdlr->add_dispatch_delegate(
        s_reason,
        hdlr_t::create<cr_access_t, &cr_access_t::handle>(this)
    );
}

void
cr_access::set_default(hdlr_t &&hdlr)
{
    m_def_hdlr = hdlr;
}

void
cr_access::set(const key_t key, hdlr_t &&hdlr)
{
    if (m_handlers.count(key) > 0) {
        return;
    }

    m_handlers[key] = hdlr;
}

void
cr_access::clear_default()
{
    set_default(hdlr_t::create<nullptr>());
    return;
}

void
cr_access::clear(const key_t key)
{
    if (m_handlers.count(key) == 0) {
        return;
    }

    m_handlers.erase(key);
    return;
}

bool
cr_access::handle(gsl::not_null<vmcs_t *> vmcs)
{
    const auto key = cra::access_type::get();

    if (m_handlers.count(key) == 0) {
        if (m_def_hdlr.is_valid()) {
             return m_def_hdlr(vmcs);
        }

        return false;
    }

    return m_handlers[key](vmcs);
}

} // namespace intel_x64
} // namespace eapis
