//
// Bareflank Hypervisor Examples
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

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>

using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_ept()
{
    ept_pointer::memory_type::set(ept_pointer::memory_type::write_back);
    ept_pointer::page_walk_length_minus_one::set(3UL);
    ept_pointer::phys_addr::set(eptp()->phys_addr());

    secondary_processor_based_vm_execution_controls::enable_ept::enable();
    intel_x64::vmx::invept_global();
}

void
vmcs_intel_x64_eapis::disable_ept()
{
    intel_x64::vmx::invept_global();
    secondary_processor_based_vm_execution_controls::enable_ept::disable();

    ept_pointer::set(0UL);
}

void
vmcs_intel_x64_eapis::unmap(integer_pointer gpa) noexcept
{
    std::lock_guard<std::mutex> guard(eptp_mutex());

    guard_exceptions([&]
    { eptp()->remove_page(gpa); });
}

void
vmcs_intel_x64_eapis::setup_ept_identity_map_1g(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pdpt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pdpt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += ept::pdpt::size_bytes)
        this->map_1g(virt, virt, ept::memory_attr::pt_wb);
}

void
vmcs_intel_x64_eapis::setup_ept_identity_map_2m(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pd::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pd::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += ept::pd::size_bytes)
        this->map_2m(virt, virt, ept::memory_attr::pt_wb);
}

void
vmcs_intel_x64_eapis::setup_ept_identity_map_4k(
    integer_pointer saddr, integer_pointer eaddr)
{
    expects((saddr & (ept::pt::size_bytes - 1)) == 0);
    expects((eaddr & (ept::pt::size_bytes - 1)) == 0);

    for (auto virt = saddr; virt < eaddr; virt += ept::pt::size_bytes)
        this->map_4k(virt, virt, ept::memory_attr::pt_wb);
}

gsl::not_null<ept_entry_intel_x64 *>
vmcs_intel_x64_eapis::gpa_to_epte(integer_pointer gpa)
{
    std::lock_guard<std::mutex> guard(eptp_mutex());
    return eptp()->find_epte(gpa);
}

std::mutex &
vmcs_intel_x64_eapis::eptp_mutex() const
{
    static std::mutex g_ept_map_mutex;
    return g_ept_map_mutex;
}

gsl::not_null<ept_intel_x64 *>
vmcs_intel_x64_eapis::eptp() const
{
    static std::unique_ptr<ept_intel_x64> g_eptp;

    if (!g_eptp)
        g_eptp = std::make_unique<ept_intel_x64>();

    return g_eptp.get();
}

void
vmcs_intel_x64_eapis::map(integer_pointer gpa, integer_pointer phys_addr, attr_type attr, size_type size)
{
    ept_entry_intel_x64 *entry = nullptr;
    std::lock_guard<std::mutex> guard(eptp_mutex());

    switch (size)
    {
        case ept::pdpt::size_bytes:
        {
            gpa &= ~(ept::pdpt::size_bytes - 1);
            phys_addr &= ~(ept::pdpt::size_bytes - 1);

            if ((entry = eptp()->add_page_1g(gpa)) != nullptr)
            {
                entry->clear();
                entry->set_phys_addr(phys_addr);
                entry->set_entry_type(true);
            }

            break;
        }

        case ept::pd::size_bytes:
        {
            gpa &= ~(ept::pd::size_bytes - 1);
            phys_addr &= ~(ept::pd::size_bytes - 1);

            if ((entry = eptp()->add_page_2m(gpa)) != nullptr)
            {
                entry->clear();
                entry->set_phys_addr(phys_addr);
                entry->set_entry_type(true);
            }

            break;
        }

        case ept::pt::size_bytes:
        {
            gpa &= ~(ept::pt::size_bytes - 1);
            phys_addr &= ~(ept::pt::size_bytes - 1);

            if ((entry = eptp()->add_page_4k(gpa)) != nullptr)
            {
                entry->clear();
                entry->set_phys_addr(phys_addr);
            }

            break;
        }
    }

    if (entry == nullptr)
        throw std::logic_error("failed to add page to EPTP");

    auto ___ = gsl::on_failure([&]
    { eptp()->remove_page(gpa); });

    switch (attr)
    {
        case ept::memory_attr::rw_uc:
        case ept::memory_attr::re_uc:
        case ept::memory_attr::eo_uc:
        case ept::memory_attr::pt_uc:
        case ept::memory_attr::tp_uc:
            entry->set_memory_type(ept::memory_type::uc);
            break;

        case ept::memory_attr::rw_wc:
        case ept::memory_attr::re_wc:
        case ept::memory_attr::eo_wc:
        case ept::memory_attr::pt_wc:
        case ept::memory_attr::tp_wc:
            entry->set_memory_type(ept::memory_type::wc);
            break;

        case ept::memory_attr::rw_wt:
        case ept::memory_attr::re_wt:
        case ept::memory_attr::eo_wt:
        case ept::memory_attr::pt_wt:
        case ept::memory_attr::tp_wt:
            entry->set_memory_type(ept::memory_type::wt);
            break;

        case ept::memory_attr::rw_wp:
        case ept::memory_attr::re_wp:
        case ept::memory_attr::eo_wp:
        case ept::memory_attr::pt_wp:
        case ept::memory_attr::tp_wp:
            entry->set_memory_type(ept::memory_type::wp);
            break;

        case ept::memory_attr::rw_wb:
        case ept::memory_attr::re_wb:
        case ept::memory_attr::eo_wb:
        case ept::memory_attr::pt_wb:
        case ept::memory_attr::tp_wb:
            entry->set_memory_type(ept::memory_type::wb);
            break;
    }

    switch (attr)
    {
        case ept::memory_attr::rw_uc:
        case ept::memory_attr::rw_wc:
        case ept::memory_attr::rw_wt:
        case ept::memory_attr::rw_wp:
        case ept::memory_attr::rw_wb:
            entry->set_read_access(true);
            entry->set_write_access(true);
            entry->set_execute_access(false);
            break;

        case ept::memory_attr::re_uc:
        case ept::memory_attr::re_wc:
        case ept::memory_attr::re_wt:
        case ept::memory_attr::re_wp:
        case ept::memory_attr::re_wb:
            entry->set_read_access(true);
            entry->set_write_access(false);
            entry->set_execute_access(true);
            break;

        case ept::memory_attr::eo_uc:
        case ept::memory_attr::eo_wc:
        case ept::memory_attr::eo_wt:
        case ept::memory_attr::eo_wp:
        case ept::memory_attr::eo_wb:
            entry->set_read_access(false);
            entry->set_write_access(false);
            entry->set_execute_access(true);
            break;

        case ept::memory_attr::pt_uc:
        case ept::memory_attr::pt_wc:
        case ept::memory_attr::pt_wt:
        case ept::memory_attr::pt_wp:
        case ept::memory_attr::pt_wb:
            entry->set_read_access(true);
            entry->set_write_access(true);
            entry->set_execute_access(true);
            break;

        case ept::memory_attr::tp_uc:
        case ept::memory_attr::tp_wc:
        case ept::memory_attr::tp_wt:
        case ept::memory_attr::tp_wp:
        case ept::memory_attr::tp_wb:
            entry->set_read_access(false);
            entry->set_write_access(false);
            entry->set_execute_access(false);
            break;

        default:
            throw std::logic_error("unsupported memory attribute");
    }
}
