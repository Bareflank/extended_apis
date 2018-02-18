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
#include <bfvmm/memory_manager/memory_manager.h>
#include <eapis/hve/arch/intel_x64/ept/root_ept.h>

namespace intel = eapis::intel_x64;
namespace mem_attr = ::intel_x64::ept::memory_attr;

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
    expects((saddr & (::intel_x64::ept::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pdpt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pdpt::size_bytes) {
        this->map_1g(gpa, gpa, mem_attr::pt_wb);
    }
}

void
intel::root_ept::setup_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (::intel_x64::ept::pd::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pd::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pd::size_bytes) {
        this->map_2m(gpa, gpa, mem_attr::pt_wb);
    }
}

void
intel::root_ept::setup_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (::intel_x64::ept::pt::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pt::size_bytes) {
        this->map_4k(gpa, gpa, mem_attr::pt_wb);
    }
}

void
intel::root_ept::unmap_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (::intel_x64::ept::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pdpt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pdpt::size_bytes) {
        this->unmap(gpa);
    }
}

void
intel::root_ept::unmap_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (::intel_x64::ept::pd::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pd::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pd::size_bytes) {
        this->unmap(gpa);
    }
}

void
intel::root_ept::unmap_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (::intel_x64::ept::pt::size_bytes - 1)) == 0);
    expects((eaddr & (::intel_x64::ept::pt::size_bytes - 1)) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += ::intel_x64::ept::pt::size_bytes) {
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
    switch (size) {
        case ::intel_x64::ept::pdpt::size_bytes:
            return m_ept->add_page_1g(gpa);

        case ::intel_x64::ept::pd::size_bytes:
            return m_ept->add_page_2m(gpa);

        case ::intel_x64::ept::pt::size_bytes:
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

    switch (size) {
        case ::intel_x64::ept::pdpt::size_bytes:
            entry.set_phys_addr(phys & ~(::intel_x64::ept::pdpt::size_bytes - 1));
            break;

        case ::intel_x64::ept::pd::size_bytes:
            entry.set_phys_addr(phys & ~(::intel_x64::ept::pd::size_bytes - 1));
            break;

        case ::intel_x64::ept::pt::size_bytes:
            entry.set_phys_addr(phys & ~(::intel_x64::ept::pt::size_bytes - 1));
            break;
    }

    switch (attr) {
        case mem_attr::rw_uc:
        case mem_attr::re_uc:
        case mem_attr::ro_uc:
        case mem_attr::eo_uc:
        case mem_attr::pt_uc:
        case mem_attr::tp_uc:
            entry.set_memory_type(::intel_x64::ept::memory_type::uc);
            break;

        case mem_attr::rw_wc:
        case mem_attr::re_wc:
        case mem_attr::ro_wc:
        case mem_attr::eo_wc:
        case mem_attr::pt_wc:
        case mem_attr::tp_wc:
            entry.set_memory_type(::intel_x64::ept::memory_type::wc);
            break;

        case mem_attr::rw_wt:
        case mem_attr::re_wt:
        case mem_attr::ro_wt:
        case mem_attr::eo_wt:
        case mem_attr::pt_wt:
        case mem_attr::tp_wt:
            entry.set_memory_type(::intel_x64::ept::memory_type::wt);
            break;

        case mem_attr::rw_wp:
        case mem_attr::re_wp:
        case mem_attr::ro_wp:
        case mem_attr::eo_wp:
        case mem_attr::pt_wp:
        case mem_attr::tp_wp:
            entry.set_memory_type(::intel_x64::ept::memory_type::wp);
            break;

        case mem_attr::rw_wb:
        case mem_attr::re_wb:
        case mem_attr::ro_wb:
        case mem_attr::eo_wb:
        case mem_attr::pt_wb:
        case mem_attr::tp_wb:
            entry.set_memory_type(::intel_x64::ept::memory_type::wb);
            break;
    }

    switch (attr) {
        case mem_attr::rw_uc:
        case mem_attr::rw_wc:
        case mem_attr::rw_wt:
        case mem_attr::rw_wp:
        case mem_attr::rw_wb:
            entry.set_read_access(true);
            entry.set_write_access(true);
            entry.set_execute_access(false);
            break;

        case mem_attr::re_uc:
        case mem_attr::re_wc:
        case mem_attr::re_wt:
        case mem_attr::re_wp:
        case mem_attr::re_wb:
            entry.set_read_access(true);
            entry.set_write_access(false);
            entry.set_execute_access(true);
            break;

        case mem_attr::ro_uc:
        case mem_attr::ro_wc:
        case mem_attr::ro_wt:
        case mem_attr::ro_wp:
        case mem_attr::ro_wb:
            entry.set_read_access(true);
            entry.set_write_access(false);
            entry.set_execute_access(false);
            break;

        case mem_attr::eo_uc:
        case mem_attr::eo_wc:
        case mem_attr::eo_wt:
        case mem_attr::eo_wp:
        case mem_attr::eo_wb:
            entry.set_read_access(false);
            entry.set_write_access(false);
            entry.set_execute_access(true);
            break;

        case mem_attr::pt_uc:
        case mem_attr::pt_wc:
        case mem_attr::pt_wt:
        case mem_attr::pt_wp:
        case mem_attr::pt_wb:
            entry.set_read_access(true);
            entry.set_write_access(true);
            entry.set_execute_access(true);
            break;

        case mem_attr::tp_uc:
        case mem_attr::tp_wc:
        case mem_attr::tp_wt:
        case mem_attr::tp_wp:
        case mem_attr::tp_wb:
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
