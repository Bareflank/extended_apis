//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include "ept_test_support.h"

namespace test_ept
{

ept_test_support::ept_test_support(HippoMocks::MockRepository &mocks)
{
    m_mock_mm = mocks.Mock<bfvmm::memory_manager>();
    mocks.OnCallFunc(bfvmm::memory_manager::instance).Return(m_mock_mm);

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::virtptr_to_physint).Do(
    [&](auto hva) { return this->mock_virtptr_to_physint(hva); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::virtint_to_physint).Do(
    [&](auto hva) { return this->mock_virtint_to_physint(hva); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::virtptr_to_physptr).Do(
    [&](auto hva) { return this->mock_virtptr_to_physptr(hva); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::virtint_to_physptr).Do(
    [&](auto hva) { return this->mock_virtint_to_physptr(hva); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::physint_to_virtptr).Do(
    [&](auto hpa) { return this->mock_physint_to_virtptr(hpa); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::physint_to_virtint).Do(
    [&](auto hpa) { return this->mock_physint_to_virtint(hpa); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::physptr_to_virtptr).Do(
    [&](auto hpa) { return this->mock_physptr_to_virtptr(hpa); });

    mocks.OnCall(m_mock_mm, bfvmm::memory_manager::physptr_to_virtint).Do(
    [&](auto hpa) { return this->mock_physptr_to_virtint(hpa); });
}

void
ept_test_support::add_mock_mapping(ept::gpa_t hva, ept::hpa_t hpa)
{
    m_mock_mem[hva] = hpa;
}

void
ept_test_support::setup_mock_empty_pml4(ept::memory_map &map)
{
    this->reset(map);
    m_saved_pml4_hva = map.m_pml4_hva;

    for (auto entry : gsl::make_span(m_pml4.get(), ept::page_table::num_entries)) {
        entry = 0ULL;
        entry = entry;
    }

    map.m_pml4_hva = reinterpret_cast<uintptr_t>(m_pml4.get());
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pml4.get()), mock_pml4_hpa);
}

void
ept_test_support::setup_mock_1g_page(ept::memory_map &map)
{
    this->reset(map);
    m_saved_pml4_hva = map.m_pml4_hva;

    auto pml4_view = gsl::make_span(m_pml4.get(), ept::page_table::num_entries);
    auto first_entry = pml4_view.begin();
    auto last_entry = pml4_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pdpt_hpa & ept::epte::phys_addr_bits::mask);

    auto pdpt_view = gsl::make_span(m_pdpt.get(), ept::page_table::num_entries);
    first_entry = pdpt_view.begin();
    last_entry = pdpt_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::entry_type::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_page_hpa & ept::epte::phys_addr_bits::mask);

    map.m_pml4_hva = reinterpret_cast<uintptr_t>(m_pml4.get());
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pml4.get()), mock_pml4_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pdpt.get()), mock_pdpt_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_page.get()), mock_page_hpa);
}

void
ept_test_support::setup_mock_2m_page(ept::memory_map &map)
{
    this->reset(map);
    m_saved_pml4_hva = map.m_pml4_hva;

    auto pml4_view = gsl::make_span(m_pml4.get(), ept::page_table::num_entries);
    auto first_entry = pml4_view.begin();
    auto last_entry = pml4_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pdpt_hpa & ept::epte::phys_addr_bits::mask);

    auto pdpt_view = gsl::make_span(m_pdpt.get(), ept::page_table::num_entries);
    first_entry = pdpt_view.begin();
    last_entry = pdpt_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pd_hpa & ept::epte::phys_addr_bits::mask);

    auto pd_view = gsl::make_span(m_pd.get(), ept::page_table::num_entries);
    first_entry = pd_view.begin();
    last_entry = pd_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::entry_type::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_page_hpa & ept::epte::phys_addr_bits::mask);

    map.m_pml4_hva = reinterpret_cast<uintptr_t>(m_pml4.get());
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pml4.get()), mock_pml4_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pdpt.get()), mock_pdpt_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pd.get()), mock_pd_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_page.get()), mock_page_hpa);
}

void
ept_test_support::setup_mock_4k_page(ept::memory_map &map)
{
    this->reset(map);
    m_saved_pml4_hva = map.m_pml4_hva;

    auto pml4_view = gsl::make_span(m_pml4.get(), ept::page_table::num_entries);
    auto first_entry = pml4_view.begin();
    auto last_entry = pml4_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pdpt_hpa & ept::epte::phys_addr_bits::mask);

    auto pdpt_view = gsl::make_span(m_pdpt.get(), ept::page_table::num_entries);
    first_entry = pdpt_view.begin();
    last_entry = pdpt_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pd_hpa & ept::epte::phys_addr_bits::mask);

    auto pd_view = gsl::make_span(m_pd.get(), ept::page_table::num_entries);
    first_entry = pd_view.begin();
    last_entry = pd_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_pt_hpa & ept::epte::phys_addr_bits::mask);

    auto pt_view = gsl::make_span(m_pt.get(), ept::page_table::num_entries);
    first_entry = pt_view.begin();
    last_entry = pt_view.end() - 1;
    ept::epte::clear(*first_entry);
    ept::epte::clear(*last_entry);
    ept::epte::read_access::enable(*last_entry);
    ept::epte::write_access::enable(*last_entry);
    ept::epte::entry_type::enable(*last_entry);
    ept::epte::set_hpa(*last_entry, mock_page_hpa & ept::epte::phys_addr_bits::mask);

    map.m_pml4_hva = reinterpret_cast<uintptr_t>(m_pml4.get());
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pml4.get()), mock_pml4_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pdpt.get()), mock_pdpt_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pd.get()), mock_pd_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_pt.get()), mock_pt_hpa);
    add_mock_mapping(reinterpret_cast<uintptr_t>(m_page.get()), mock_page_hpa);
}

void
ept_test_support::reset(ept::memory_map &map)
{
    m_mock_mem.clear();
    m_next_phys_addr = 0xF00D0000;

    for (auto entry : gsl::make_span(m_pml4.get(), ept::page_table::num_entries)) {
        entry = 0xffffffffffffffff;
        entry = entry;
    }

    for (auto entry : gsl::make_span(m_pdpt.get(), ept::page_table::num_entries)) {
        entry = 0xffffffffffffffff;
        entry = entry;
    }

    for (auto entry : gsl::make_span(m_pd.get(), ept::page_table::num_entries)) {
        entry = 0xffffffffffffffff;
        entry = entry;
    }

    for (auto entry : gsl::make_span(m_pt.get(), ept::page_table::num_entries)) {
        entry = 0xffffffffffffffff;
        entry = entry;
    }

    for (auto entry : gsl::make_span(m_page.get(), ept::page_table::num_entries)) {
        entry = gsl::byte(0xff);
        entry = entry;
    }

    if (m_saved_pml4_hva) {
        map.m_pml4_hva = m_saved_pml4_hva;
        m_saved_pml4_hva = 0;
    }
}

uintptr_t
ept_test_support::mock_virtptr_to_physint(void *hva)
{
    return mock_virtint_to_physint(reinterpret_cast<ept::hva_t>(hva));
}

void *
ept_test_support::mock_virtptr_to_physptr(void *hva)
{
    return reinterpret_cast<void *>(mock_virtptr_to_physint(hva));
}

uintptr_t
ept_test_support::mock_virtint_to_physint(uintptr_t hva)
{
    if (m_mock_mem.count(hva)) {
        return m_mock_mem.at(hva);
    }

    m_next_phys_addr += 0x1000;
    m_mock_mem[hva] = m_next_phys_addr;
    return m_next_phys_addr;
}

void *
ept_test_support::mock_virtint_to_physptr(uintptr_t hva)
{
    return reinterpret_cast<void *>(mock_virtint_to_physint(hva));
}

void *
ept_test_support::mock_physint_to_virtptr(uintptr_t hpa)
{
    return reinterpret_cast<void *>(mock_physint_to_virtint(hpa));
}

void *
ept_test_support::mock_physptr_to_virtptr(void *hpa)
{
    return mock_physint_to_virtptr(reinterpret_cast<uintptr_t>(hpa));
}

uintptr_t
ept_test_support::mock_physint_to_virtint(uintptr_t hpa)
{
    for (auto const &x : m_mock_mem) {
        if (x.second == hpa) {
            return x.first;
        }
    }
    std::stringstream msg;
    msg << "invalid test guest physical address: " << std::hex << "0x" << hpa;
    throw std::logic_error(msg.str().c_str());
}

uintptr_t
ept_test_support::mock_physptr_to_virtint(void *hpa)
{
    return reinterpret_cast<uintptr_t>(mock_physptr_to_virtptr(hpa));
}

}
