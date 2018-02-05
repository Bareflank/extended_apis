//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <bfexception.h>
#include "../../../../../include/hve/arch/intel_x64/vmcs/root_ept.h"
#include <bfvmm/memory_manager/memory_manager_x64.h>

namespace ept = ept;
namespace intel = eapis::hve::intel_x64;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

intel::root_ept::root_ept() :
    m_ept{std::make_unique<ept>(&m_eptp)}
{ }

intel::root_ept::eptp_type
intel::root_ept::eptp()
{ return m_eptp; }

void
intel::root_ept::unmap(integer_pointer gpa) noexcept
{
    std::lock_guard<std::mutex> guard(m_mutex);
    unmap_page(gpa);
}

void
intel::root_ept::setup_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pdpt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pdpt::size_bytes)
        this->map_1g(gpa, gpa, ept::memory_attr::pt_wb);
}

void
intel::root_ept::setup_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pd::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pd::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pd::size_bytes)
        this->map_2m(gpa, gpa, ept::memory_attr::pt_wb);
}

void
intel::root_ept::setup_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pt::size_bytes)
        this->map_4k(gpa, gpa, ept::memory_attr::pt_wb);
}

void
intel::root_ept::unmap_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pdpt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pdpt::size_bytes)
        this->unmap(gpa);
    }
}

void
intel::root_ept::unmap_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pd::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pd::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pd::size_bytes)
        this->unmap(gpa);
    }
}

void
intel::root_ept::unmap_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ept::pt::size_bytes)
        this->unmap(gpa);
    }
}

intel::ept_entry
intel::root_ept::gpa_to_epte(integer_pointer gpa) const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_ept->gpa_to_epte(gpa);
}

intel::root_ept::memory_descriptor_list
intel::root_ept::ept_to_mdl() const
{
    std::lock_guard<std::mutex> guard(m_mutex);
    return m_ept->ept_to_mdl();
}

intel::ept_entry
intel::root_ept::add_page(integer_pointer gpa, size_type size)
{
    switch (size)
    {
        case ept::pdpt::size_bytes:
            return m_ept->add_page_1g(gpa);

        case ept::pd::size_bytes:
            return m_ept->add_page_2m(gpa);

        case ept::pt::size_bytes:
            return m_ept->add_page_4k(gpa);

        default:
            throw std::logic_error("invalid ept size");
    }
}

void
intel::root_ept::map_page(integer_pointer gpa, integer_pointer phys, attr_type attr, size_type size)
{
    std::lock_guard<std::mutex> guard(m_mutex);

    auto &&entry = add_page(gpa, size);

    auto ___ = gsl::on_failure([&]
    { this->unmap_page(gpa); });

    switch (size)
    {
        case ept::pdpt::size_bytes:
            entry.set_phys_addr(phys & ~(ept::pdpt::size_bytes - 1));
            break;

        case ept::pd::size_bytes:
            entry.set_phys_addr(phys & ~(ept::pd::size_bytes - 1));
            break;

        case ept::pt::size_bytes:
            entry.set_phys_addr(phys & ~(ept::pt::size_bytes - 1));
            break;
    }

    switch (attr)
    {
        case ept::memory_attr::rw_uc:
        case ept::memory_attr::re_uc:
        case ept::memory_attr::ro_uc:
        case ept::memory_attr::eo_uc:
        case ept::memory_attr::pt_uc:
        case ept::memory_attr::tp_uc:
            entry.set_memory_type(ept::memory_type::uc);
            break;

        case ept::memory_attr::rw_wc:
        case ept::memory_attr::re_wc:
        case ept::memory_attr::ro_wc:
        case ept::memory_attr::eo_wc:
        case ept::memory_attr::pt_wc:
        case ept::memory_attr::tp_wc:
            entry.set_memory_type(ept::memory_type::wc);
            break;

        case ept::memory_attr::rw_wt:
        case ept::memory_attr::re_wt:
        case ept::memory_attr::ro_wt:
        case ept::memory_attr::eo_wt:
        case ept::memory_attr::pt_wt:
        case ept::memory_attr::tp_wt:
            entry.set_memory_type(ept::memory_type::wt);
            break;

        case ept::memory_attr::rw_wp:
        case ept::memory_attr::re_wp:
        case ept::memory_attr::ro_wp:
        case ept::memory_attr::eo_wp:
        case ept::memory_attr::pt_wp:
        case ept::memory_attr::tp_wp:
            entry.set_memory_type(ept::memory_type::wp);
            break;

        case ept::memory_attr::rw_wb:
        case ept::memory_attr::re_wb:
        case ept::memory_attr::ro_wb:
        case ept::memory_attr::eo_wb:
        case ept::memory_attr::pt_wb:
        case ept::memory_attr::tp_wb:
            entry.set_memory_type(ept::memory_type::wb);
            break;
    }

    switch (attr)
    {
        case ept::memory_attr::rw_uc:
        case ept::memory_attr::rw_wc:
        case ept::memory_attr::rw_wt:
        case ept::memory_attr::rw_wp:
        case ept::memory_attr::rw_wb:
            entry.set_read_access(true);
            entry.set_write_access(true);
            entry.set_execute_access(false);
            break;

        case ept::memory_attr::re_uc:
        case ept::memory_attr::re_wc:
        case ept::memory_attr::re_wt:
        case ept::memory_attr::re_wp:
        case ept::memory_attr::re_wb:
            entry.set_read_access(true);
            entry.set_write_access(false);
            entry.set_execute_access(true);
            break;

        case ept::memory_attr::ro_uc:
        case ept::memory_attr::ro_wc:
        case ept::memory_attr::ro_wt:
        case ept::memory_attr::ro_wp:
        case ept::memory_attr::ro_wb:
            entry.set_read_access(true);
            entry.set_write_access(false);
            entry.set_execute_access(false);
            break;

        case ept::memory_attr::eo_uc:
        case ept::memory_attr::eo_wc:
        case ept::memory_attr::eo_wt:
        case ept::memory_attr::eo_wp:
        case ept::memory_attr::eo_wb:
            entry.set_read_access(false);
            entry.set_write_access(false);
            entry.set_execute_access(true);
            break;

        case ept::memory_attr::pt_uc:
        case ept::memory_attr::pt_wc:
        case ept::memory_attr::pt_wt:
        case ept::memory_attr::pt_wp:
        case ept::memory_attr::pt_wb:
            entry.set_read_access(true);
            entry.set_write_access(true);
            entry.set_execute_access(true);
            break;

        case ept::memory_attr::tp_uc:
        case ept::memory_attr::tp_wc:
        case ept::memory_attr::tp_wt:
        case ept::memory_attr::tp_wp:
        case ept::memory_attr::tp_wb:
            entry.set_read_access(false);
            entry.set_write_access(false);
            entry.set_execute_access(false);
            break;

        default:
            throw std::logic_error("unsupported memory attribute");
    }
}

void
intel::root_ept::unmap_page(integer_pointer gpa) noexcept
{
    guard_exceptions([&]
    { m_ept->remove_page(gpa); });
}
