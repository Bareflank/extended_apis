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

ept_violation_handler::ept_violation_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::ept_violation,
        ::handler_delegate_t::create<ept_violation_handler, &ept_violation_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
ept_violation_handler::add_read_handler(
    const handler_delegate_t &d)
{ m_read_handlers.push_front(d); }

void
ept_violation_handler::add_write_handler(
    const handler_delegate_t &d)
{ m_write_handlers.push_front(d); }

void
ept_violation_handler::add_execute_handler(
    const handler_delegate_t &d)
{ m_execute_handlers.push_front(d); }

void
ept_violation_handler::set_default_read_handler(
    const ::handler_delegate_t &d)
{ m_default_read_handler = d; }

void
ept_violation_handler::set_default_write_handler(
    const ::handler_delegate_t &d)
{ m_default_write_handler = d; }

void
ept_violation_handler::set_default_execute_handler(
    const ::handler_delegate_t &d)
{ m_default_execute_handler = d; }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_violation_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    using namespace vmcs_n;
    auto qual = exit_qualification::ept_violation::get();

    struct info_t info = {
        guest_linear_address::get(),
        guest_physical_address::get(),
        qual,
        true
    };

    if (exit_qualification::ept_violation::data_read::is_enabled(qual)) {
        return handle_read(vcpu, info);
    }

    if (exit_qualification::ept_violation::data_write::is_enabled(qual)) {
        return handle_write(vcpu, info);
    }

    if (exit_qualification::ept_violation::instruction_fetch::is_enabled(qual)) {
        return handle_execute(vcpu, info);
    }

    throw std::runtime_error(
        "ept_violation_handler::handle: unhandled ept violation"
    );
}

bool
ept_violation_handler::handle_read(gsl::not_null<vcpu_t *> vcpu, info_t &info)
{
    for (const auto &d : m_read_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return advance(vcpu);
            }

            return true;
        }
    }

    if (m_default_read_handler.is_valid()) {
        return m_default_read_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept read violation"
    );
}

bool
ept_violation_handler::handle_write(gsl::not_null<vcpu_t *> vcpu, info_t &info)
{
    for (const auto &d : m_write_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return advance(vcpu);
            }

            return true;
        }
    }

    if (m_default_write_handler.is_valid()) {
        return m_default_write_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept write violation"
    );
}

bool
ept_violation_handler::handle_execute(gsl::not_null<vcpu_t *> vcpu, info_t &info)
{
    for (const auto &d : m_execute_handlers) {
        if (d(vcpu, info)) {

            if (!info.ignore_advance) {
                return advance(vcpu);
            }

            return true;
        }
    }

    if (m_default_execute_handler.is_valid()) {
        return m_default_execute_handler(vcpu);
    }

    throw std::runtime_error(
        "ept_violation_handler: unhandled ept execute violation"
    );
}

}
