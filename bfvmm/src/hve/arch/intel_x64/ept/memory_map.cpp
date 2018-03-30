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

#include <bfvmm/memory_manager/memory_manager.h>
#include "hve/arch/intel_x64/ept/memory_map.h"
#include "hve/arch/intel_x64/ept/intrinsics.h"

namespace eapis
{
namespace intel_x64
{
namespace ept
{

memory_map::memory_map()
{
    auto pml4 = new epte_t[page_table::num_entries]();
    m_pml4_hva = reinterpret_cast<hva_t>(pml4);
    m_pml4_hpa = g_mm->virtint_to_physint(m_pml4_hva);
}

memory_map::~memory_map()
{
    auto pml4 = reinterpret_cast<epte_t *>(m_pml4_hva);
    auto pml4_view = gsl::make_span(pml4, page_table::num_entries);

    for (auto pml4e : pml4_view) {
        if (epte::is_present(pml4e) && !epte::is_leaf_entry(pml4e)) {
            free_page_table(pml4e);
        }
        epte::clear(pml4e);
    }

    delete[] pml4;
}

epte_t &
memory_map::map(gpa_t gpa, hpa_t hpa, uint64_t size)
{
    switch (size) {
        case pdpte::page_size_bytes:
            expects(pdpte::page_address::is_aligned(hpa));
            return this->map_pdpte_to_page(gpa, hpa);

        case pde::page_size_bytes:
            expects(pde::page_address::is_aligned(hpa));
            return this->map_pde_to_page(gpa, hpa);

        case pte::page_size_bytes:
            expects(pte::page_address::is_aligned(hpa));
            return this->map_pte_to_page(gpa, hpa);

        default:
            throw std::logic_error("map: invalid ept page size specified");
    }
}

void
memory_map::unmap(gpa_t gpa)
{
    auto &leaf = gpa_to_epte(gpa);
    epte::clear(leaf);
}

epte_t &
memory_map::gpa_to_epte(gpa_t gpa)
{
    auto &pml4e = this->gpa_to_pml4e(gpa);
    if (!epte::is_present(pml4e)) {
        throw std::runtime_error("gpa_to_epte: failed to resolve gpa->epte, "
                                 "gpa is not mapped at the 512GB level");
    }

    auto &pdpte = this->gpa_to_pdpte(gpa, pml4e);
    if (!epte::is_present(pdpte)) {
        throw std::runtime_error("gpa_to_epte: failed to resolve gpa->epte, "
                                 "gpa is not mapped at the 1GB level");
    }
    if (epte::is_leaf_entry(pdpte)) {
        return pdpte;
    }

    auto &pde = this->gpa_to_pde(gpa, pdpte);
    if (!epte::is_present(pde)) {
        throw std::runtime_error("gpa_to_epte: failed to resolve gpa->epte, "
                                 "gpa is not mapped at the 2MB level");
    }
    if (epte::is_leaf_entry(pde)) {
        return pde;
    }

    auto &pte = this->gpa_to_pte(gpa, pde);
    if (!epte::is_present(pte)) {
        throw std::runtime_error("gpa_to_epte: failed to resolve gpa->epte, "
                                 "gpa is not mapped at the 4KB level");
    }
    if (epte::is_leaf_entry(pte)) {
        return pte;
    }

    throw std::runtime_error("gpa_to_epte: extended page tables corrupted");
}

hpa_t
memory_map::gpa_to_hpa(gpa_t gpa)
{
    auto &pml4e = this->gpa_to_pml4e(gpa);
    if (!epte::is_present(pml4e)) {
        throw std::runtime_error("gpa_to_hpa: failed to resolve gpa->epte, gpa "
                                 "is not mapped at the 512GB level");
    }

    auto &pdpte = this->gpa_to_pdpte(gpa, pml4e);
    if (!epte::is_present(pdpte)) {
        throw std::runtime_error("gpa_to_hpa: failed to resolve gpa->epte, gpa "
                                 "is not mapped at the 1GB level");
    }
    if (epte::is_leaf_entry(pdpte)) {
        return pdpte::page_address::get_effective_address(pdpte, gpa);
    }

    auto &pde = this->gpa_to_pde(gpa, pdpte);
    if (!epte::is_present(pde)) {
        throw std::runtime_error("gpa_to_hpa: failed to resolve gpa->epte, gpa "
                                 "is not mapped at the 2MB level");
    }
    if (epte::is_leaf_entry(pde)) {
        return pde::page_address::get_effective_address(pde, gpa);
    }

    auto &pte = this->gpa_to_pte(gpa, pde);
    if (!epte::is_present(pte)) {
        throw std::runtime_error("gpa_to_hpa: failed to resolve gpa->epte, gpa "
                                 "is not mapped at the 4KB level");
    }
    if (epte::is_leaf_entry(pte)) {
        return pte::page_address::get_effective_address(pte, gpa);
    }

    throw std::runtime_error("gpa_to_hpa: extended page tables corrupted");
}

std::vector<memory_descriptor>
memory_map::to_mdl() const
{
    std::vector<memory_descriptor> mdl;
    mdl.push_back({m_pml4_hpa, m_pml4_hva, MEMORY_TYPE_R | MEMORY_TYPE_W});

    this->to_mdl(mdl, reinterpret_cast<epte_t *>(m_pml4_hva));

    return mdl;
}

hpa_t
memory_map::hpa() const
{ return m_pml4_hpa; }

hpa_t
memory_map::allocate_page_table()
{
    auto pt_hva = new epte_t [page_table::num_entries]();
    auto pt_hpa = g_mm->virtptr_to_physint(pt_hva);

    return pt_hpa;
}

void
memory_map::allocate_page_table(epte_t &entry)
{
    auto pt_hpa = this->allocate_page_table();

    epte::read_access::enable(entry);
    epte::write_access::enable(entry);
    epte::execute_access::enable(entry);
    epte::memory_type::set(entry, epte::memory_type::wb);
    epte::set_hpa(entry, pt_hpa);
}

void
memory_map::free_page_table(epte_t &entry)
{
    auto pt_hpa = epte::hpa(entry);
    auto pt_hva = g_mm->physint_to_virtptr(pt_hpa);
    auto page_table = static_cast<epte_t *>(pt_hva);

    auto pt_view = gsl::make_span(page_table, page_table::num_entries);

    for (auto pte : pt_view) {
        if (epte::is_present(pte) && !epte::is_leaf_entry(pte)) {
            this->free_page_table(pte);
        }
    }

    epte::clear(entry);
    delete[] page_table;
}

void
memory_map::map_entry_to_page_frame(epte_t &entry, hpa_t hpa)
{
    epte::read_access::enable(entry);
    epte::write_access::enable(entry);
    epte::memory_type::set(entry, epte::memory_type::wb);
    epte::entry_type::enable(entry);
    epte::set_hpa(entry, hpa);
}

epte_t &
memory_map::gpa_to_pml4e(gpa_t gpa)
{
    auto pml4e_offset = gpa::pml4_index::get_offset(gpa);
    auto pml4_hva = g_mm->physint_to_virtint(m_pml4_hpa);
    auto pml4e_hva = pml4_hva + pml4e_offset;

    return *reinterpret_cast<epte_t *>(pml4e_hva);
}

epte_t &
memory_map::gpa_to_pdpte(gpa_t gpa, epte_t &pml4e)
{
    auto pdpte_offset = gpa::pdpt_index::get_offset(gpa);
    auto pdpt_hpa = epte::hpa(pml4e);
    auto pdpt_hva = g_mm->physint_to_virtint(pdpt_hpa);
    auto pdpte_hva = pdpt_hva + pdpte_offset;

    return *reinterpret_cast<epte_t *>(pdpte_hva);
}

epte_t &
memory_map::gpa_to_pde(gpa_t gpa, epte_t &pdpte)
{
    auto pde_offset = gpa::pd_index::get_offset(gpa);
    auto pd_hpa = epte::hpa(pdpte);
    auto pd_hva = g_mm->physint_to_virtint(pd_hpa);
    auto pde_hva = pd_hva + pde_offset;

    return *reinterpret_cast<epte_t *>(pde_hva);
}

epte_t &
memory_map::gpa_to_pte(gpa_t gpa, epte_t &pde)
{
    auto pte_offset = gpa::pt_index::get_offset(gpa);
    auto pt_hpa = epte::hpa(pde);
    auto pt_hva = g_mm->physint_to_virtint(pt_hpa);
    auto pte_hva = pt_hva + pte_offset;

    return *reinterpret_cast<epte_t *>(pte_hva);
}

epte_t &
memory_map::map_pdpte_to_page(gpa_t gpa, hpa_t hpa)
{
    auto &pml4e = this->gpa_to_pml4e(gpa);
    if (!epte::is_present(pml4e)) {
        auto pdpt_hpa = this->allocate_page_table();

        epte::read_access::enable(pml4e);
        epte::write_access::enable(pml4e);
        epte::set_hpa(pml4e, pdpt_hpa);
    }

    auto &pdpte = this->gpa_to_pdpte(gpa, pml4e);
    if (epte::is_present(pdpte)) {
        throw std::runtime_error("map_pdpte_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 1GB level");
    }

    this->map_entry_to_page_frame(pdpte, hpa);

    return pdpte;
}

epte_t &
memory_map::map_pde_to_page(gpa_t gpa, hpa_t hpa)
{
    auto &pml4e = this->gpa_to_pml4e(gpa);
    if (!epte::is_present(pml4e)) {
        auto pdpt_hpa = this->allocate_page_table();

        epte::read_access::enable(pml4e);
        epte::write_access::enable(pml4e);
        epte::set_hpa(pml4e, pdpt_hpa);
    }

    auto &pdpte = this->gpa_to_pdpte(gpa, pml4e);
    if (epte::entry_type::is_enabled(pdpte)) {
        throw std::runtime_error("map_pde_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 1GB level");
    }
    if (!epte::is_present(pdpte)) {
        this->allocate_page_table(pdpte);
    }

    auto &pde = this->gpa_to_pde(gpa, pdpte);
    if (epte::is_present(pde)) {
        throw std::runtime_error("map_pde_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 2MB level");
    }

    this->map_entry_to_page_frame(pde, hpa);

    return pde;
}

epte_t &
memory_map::map_pte_to_page(gpa_t gpa, hpa_t hpa)
{
    auto &pml4e = this->gpa_to_pml4e(gpa);
    if (!epte::is_present(pml4e)) {
        auto pdpt_hpa = this->allocate_page_table();

        epte::read_access::enable(pml4e);
        epte::write_access::enable(pml4e);
        epte::set_hpa(pml4e, pdpt_hpa);
    }

    auto &pdpte = this->gpa_to_pdpte(gpa, pml4e);
    if (epte::entry_type::is_enabled(pdpte)) {
        throw std::runtime_error("map_pte_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 1GB level");
    }
    if (!epte::is_present(pdpte)) {
        this->allocate_page_table(pdpte);
    }

    auto &pde = this->gpa_to_pde(gpa, pdpte);
    if (epte::entry_type::is_enabled(pde)) {
        throw std::runtime_error("map_pte_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 2MB level");
    }
    if (!epte::is_present(pde)) {
        this->allocate_page_table(pde);
    }

    auto &pte = this->gpa_to_pte(gpa, pde);
    if (epte::is_present(pte)) {
        throw std::runtime_error("map_pte_to_page: failed to map gpa, gpa is "
                                 "already mapped at the 4KB level");
    }

    this->map_entry_to_page_frame(pte, hpa);
    return pte;
}

void
memory_map::to_mdl(std::vector<memory_descriptor> &mdl, epte_t *page_table) const
{
    auto pt_view = gsl::make_span(page_table, page_table::num_entries);
    for (auto pte : pt_view) {
        if (epte::is_present(pte) && !epte::is_leaf_entry(pte)) {
            auto phys = epte::hpa(pte);
            auto virt = g_mm->physint_to_virtint(phys);
            mdl.push_back({phys, virt, MEMORY_TYPE_R | MEMORY_TYPE_W});

            this->to_mdl(mdl, reinterpret_cast<epte_t *>(virt));
        }
    }
}

}
}
}
