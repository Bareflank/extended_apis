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

#include <bfvector.h>

#include <vmcs/ept_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>

#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>

using namespace x64;
using namespace intel_x64;

ept_intel_x64::ept_intel_x64(pointer epte)
{
    m_ept = std::make_unique<integer_pointer[]>(ept::num_entries);

    ept_entry_intel_x64 entry{epte};
    entry.clear();
    entry.set_phys_addr(g_mm->virtptr_to_physint(m_ept.get()));
    entry.set_read_access(true);
    entry.set_write_access(true);
    entry.set_execute_access(true);
}

ept_entry_intel_x64
ept_intel_x64::add_page(integer_pointer gpa, integer_pointer bits, integer_pointer end)
{
    auto index = ept::index(gpa, bits);

    if (bits > end) {

        if (m_epts.empty()) {
            m_epts = std::vector<std::unique_ptr<ept_intel_x64>>(ept::num_entries);
        }

        auto iter = bfn::find(m_epts, index);
        if (!(*iter)) {
            auto view = gsl::make_span(m_ept, ept::num_entries);
            (*iter) = std::make_unique<ept_intel_x64>(&view.at(index));
        }

        return (*iter)->add_page(gpa, bits - ept::pt::size, end);
    }

    if (!m_epts.empty()) {
        m_epts.clear();
        m_epts.shrink_to_fit();
    }

    auto view = gsl::make_span(m_ept, ept::num_entries);
    return ept_entry_intel_x64(&view.at(index));
}

void
ept_intel_x64::remove_page(integer_pointer gpa, integer_pointer bits)
{
    auto index = ept::index(gpa, bits);

    if (!m_epts.empty()) {

        auto iter = bfn::find(m_epts, index);
        if (auto pt = (*iter).get()) {

            pt->remove_page(gpa, bits - ept::pt::size);
            if (pt->empty()) {

                (*iter) = nullptr;

                auto view = gsl::make_span(m_ept, ept::num_entries);
                view.at(index) = 0;
            }
        }
    }
    else {

        auto view = gsl::make_span(m_ept, ept::num_entries);
        view.at(index) = 0;

        return;
    }
}

ept_entry_intel_x64
ept_intel_x64::gpa_to_epte(integer_pointer gpa, integer_pointer bits) const
{
    auto index = ept::index(gpa, bits);

    if (!m_epts.empty()) {

        auto iter = bfn::cfind(m_epts, index);
        if (auto pt = (*iter).get()) {
            return pt->gpa_to_epte(gpa, bits - ept::pt::size);
        }

        throw std::runtime_error("unable to locate epte. invalid gpaess");
    }

    auto view = gsl::make_span(m_ept, ept::num_entries);
    return ept_entry_intel_x64(&view.at(index));
}

ept_intel_x64::memory_descriptor_list
ept_intel_x64::ept_to_mdl(memory_descriptor_list &mdl) const
{
    auto virt = reinterpret_cast<uintptr_t>(m_ept.get());
    auto phys = g_mm->virtint_to_physint(virt);
    auto type = MEMORY_TYPE_R | MEMORY_TYPE_W;

    mdl.push_back({phys, virt, type});

    for (const auto &pt : m_epts) {
        if (pt != nullptr) {
            pt->ept_to_mdl(mdl);
        }
    }

    return mdl;
}

bool
ept_intel_x64::empty() const noexcept
{
    auto size = 0UL;
    auto view = gsl::make_span(m_ept, ept::num_entries);

    for (auto element : view) {
        size += element != 0 ? 1U : 0U;
    }

    return size == 0;
}

ept_intel_x64::size_type
ept_intel_x64::global_size() const noexcept
{
    auto size = 0UL;
    auto view = gsl::make_span(m_ept, ept::num_entries);

    for (auto element : view) {
        size += element != 0 ? 1U : 0U;
    }

    for (const auto &pt : m_epts) {
        if (pt != nullptr) {
            size += pt->global_size();
        }
    }

    return size;
}

ept_intel_x64::size_type
ept_intel_x64::global_capacity() const noexcept
{
    auto size = m_epts.capacity();

    for (const auto &pt : m_epts) {
        if (pt != nullptr) {
            size += pt->global_capacity();
        }
    }

    return size;
}
