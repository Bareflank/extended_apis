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

#include <arch/x64/misc.h>
#include <bfvector.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <eapis/hve/arch/intel_x64/ept/ept.h>

namespace intel = eapis::intel_x64;

intel::ept::ept(pointer epte)
{
    m_ept = std::make_unique<integer_pointer[]>(::intel_x64::ept::num_entries);

    auto &&entry = intel::ept_entry(epte);
    entry.clear();
    entry.set_phys_addr(g_mm->virtptr_to_physint(m_ept.get()));
    entry.set_read_access(true);
    entry.set_write_access(true);
    entry.set_execute_access(true);
}

intel::ept_entry
intel::ept::get_entry(index_type index)
{
    if (index >= ::intel_x64::ept::num_entries) {
        throw std::invalid_argument("index must be less than ::intel_x64::ept::num_entries");
    }

    auto table = gsl::make_span(m_ept, ::intel_x64::ept::num_entries);
    return intel::ept_entry(&table.at(index));
}

intel::ept_entry
intel::ept::add_page(integer_pointer gpa, integer_pointer bits, integer_pointer end)
{
    auto index = ::intel_x64::ept::index(gpa, bits);
    auto uindex = static_cast<std::make_unsigned<decltype(index)>::type>(index);
    auto entry = get_entry(uindex);

    if (bits > end) {
        if (entry.entry_type()) {
            throw std::logic_error("unmap gpa before adding new page");
        }

        if (m_epts.empty()) {
            m_epts = std::vector<std::unique_ptr<ept>>(::intel_x64::ept::num_entries);
        }

        auto iter = bfn::find(m_epts, index);
        if (nullptr == *iter) {
            auto view = gsl::make_span(m_ept, ::intel_x64::ept::num_entries);
            *iter = std::make_unique<ept>(&view.at(index));
        }

        return (*iter)->add_page(gpa, bits - ::intel_x64::ept::pt::size, end);
    }

    if (!m_epts.empty()) {
        auto iter = bfn::find(m_epts, index);
        if (nullptr != *iter) {
            throw std::logic_error("unmap gpa before adding new page");
        }
    }

    if (entry.entry_type()) {
        return entry;
    }

    entry.clear();
    entry.set_entry_type(true);
    return entry;
}

void
intel::ept::remove_page(integer_pointer gpa, integer_pointer bits)
{
    auto index = ::intel_x64::ept::index(gpa, bits);
    auto uindex = static_cast<std::make_unsigned<decltype(index)>::type>(index);
    auto entry = get_entry(uindex);

    if (entry.entry_type()) {
        entry.clear();
        return;
    }

    if (!m_epts.empty()) {
        auto iter = bfn::find(m_epts, index);
        if (auto pt = (*iter).get()) {
            pt->remove_page(gpa, bits - ::intel_x64::ept::pt::size);
            if (pt->empty()) {
                (*iter) = nullptr;
                entry.clear();
            }
        }
    }
}

intel::ept_entry
intel::ept::gpa_to_epte(integer_pointer gpa, integer_pointer bits) const
{
    auto &&index = ::intel_x64::ept::index(gpa, bits);

    if (!m_epts.empty()) {
        auto &&iter = bfn::cfind(m_epts, index);
        if (auto pt = (*iter).get()) {
            return pt->gpa_to_epte(gpa, bits - ::intel_x64::ept::pt::size);
        }

        throw std::runtime_error("unable to locate epte. invalid gpaess");
    }

    auto &&view = gsl::make_span(m_ept, ::intel_x64::ept::num_entries);
    return intel::ept_entry(&view.at(index));
}

intel::ept::memory_descriptor_list
intel::ept::ept_to_mdl(memory_descriptor_list &mdl) const
{
    auto &&virt = reinterpret_cast<uintptr_t>(m_ept.get());
    auto &&phys = g_mm->virtint_to_physint(virt);
    auto &&type = MEMORY_TYPE_R | MEMORY_TYPE_W;

    mdl.push_back({phys, virt, type});

    for (const auto &pt : m_epts)
        if (pt != nullptr) { pt->ept_to_mdl(mdl); }

    return mdl;
}

bool
intel::ept::empty() const noexcept
{
    auto size = 0UL;

    auto &&view = gsl::make_span(m_ept, ::intel_x64::ept::num_entries);
    for (auto element : view) {
        size += element != 0 ? 1U : 0U;
    }

    return size == 0;
}

intel::ept::size_type
intel::ept::global_size() const noexcept
{
    auto size = 0UL;

    auto &&view = gsl::make_span(m_ept, ::intel_x64::ept::num_entries);
    for (auto element : view) {
        size += element != 0 ? 1U : 0U;
    }

    for (const auto &pt : m_epts)
        if (pt != nullptr) { size += pt->global_size(); }

    return size;
}

intel::ept::size_type
intel::ept::global_capacity() const noexcept
{
    auto size = m_epts.capacity();

    for (const auto &pt : m_epts)
        if (pt != nullptr) { size += pt->global_capacity(); }

    return size;
}
