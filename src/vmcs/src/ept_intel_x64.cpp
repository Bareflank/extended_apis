//
// Bareflank Hypervisor
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

#include <vmcs/ept_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

#include <intrinsics/x64.h>
using namespace x64;
using namespace intel_x64;

ept_intel_x64::ept_intel_x64(pointer epte) :
    ept_entry_intel_x64(epte != nullptr ? epte : (&m_bitbucket)),
    m_size(0),
    m_bitbucket(0),
    m_eptes(ept::num_entries)
{
    m_ept_owner = std::make_unique<integer_pointer[]>(ept::num_entries);
    m_ept = gsl::span<integer_pointer>(m_ept_owner, ept::num_entries);

    this->clear();
    this->set_phys_addr(g_mm->virtptr_to_physint(m_ept_owner.get()));
    this->set_read_access(true);
    this->set_write_access(true);
    this->set_execute_access(true);
}

ept_intel_x64::size_type
ept_intel_x64::global_size() const noexcept
{
    auto size = m_size;

    for (const auto &epte : m_eptes)
    {
        if (auto pt = dynamic_cast<ept_intel_x64 *>(epte.get()))
            size += pt->global_size();
    }

    return size;
}

template<class T> std::unique_ptr<T>
ept_intel_x64::add_epte(pointer p)
{
    m_size++;
    return std::make_unique<T>(p);
}

template<class T> std::unique_ptr<T>
ept_intel_x64::remove_epte()
{
    m_size--;
    return nullptr;
}

gsl::not_null<ept_entry_intel_x64 *>
ept_intel_x64::add_page(
    integer_pointer addr, integer_pointer bits, integer_pointer end_bits)
{
    auto &&index = ept::index(addr, bits);

    if (bits > end_bits)
    {
        auto &&iter = bfn::find(m_eptes, index);
        if (!*iter)
            *iter = add_epte<ept_intel_x64>(&m_ept.at(index));

        if (auto epte = dynamic_cast<ept_intel_x64 *>(iter->get()))
            return epte->add_page(addr, bits - ept::pt::size, end_bits);
    }

    auto &&iter = bfn::find(m_eptes, index);
    if (*iter)
        throw std::runtime_error("add_page: page mapping already exists");

    *iter = add_epte<ept_entry_intel_x64>(&m_ept.at(index));
    return iter->get();
}

void
ept_intel_x64::remove_page(
    integer_pointer addr, integer_pointer bits)
{
    auto &&iter = bfn::find(m_eptes, ept::index(addr, bits));
    if (!*iter)
        throw std::runtime_error("remove_page: invalid address");

    if (auto epte = dynamic_cast<ept_intel_x64 *>(iter->get()))
    {
        epte->remove_page(addr, bits - ept::pt::size);

        if (epte->empty())
            *iter = remove_epte<ept_entry_intel_x64>();
    }
    else
    {
        *iter = remove_epte<ept_entry_intel_x64>();
    }
}

gsl::not_null<ept_entry_intel_x64 *>
ept_intel_x64::find_epte(
    integer_pointer addr, integer_pointer bits)
{
    auto &&iter = bfn::find(m_eptes, ept::index(addr, bits));
    if (!*iter)
        throw std::runtime_error("find_epte: invalid address");

    if (auto epte = dynamic_cast<ept_intel_x64 *>(iter->get()))
        return epte->find_epte(addr, bits - ept::pt::size);

    return iter->get();
}
