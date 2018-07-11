//
// Bareflank Hypervisor
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

#ifndef EPT_MMAP_INTEL_X64_H
#define EPT_MMAP_INTEL_X64_H

#include <vector>

#include <bfgsl.h>
#include <bfdebug.h>

#include <intrinsics.h>
#include <bfvmm/memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_MEMORY_MANAGER
#ifdef SHARED_MEMORY_MANAGER
#define EXPORT_MEMORY_MANAGER EXPORT_SYM
#else
#define EXPORT_MEMORY_MANAGER IMPORT_SYM
#endif
#else
#define EXPORT_MEMORY_MANAGER
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{
namespace ept
{

/// EPT Memory Map
///
/// This class constructs a set of EPT page tables, and provides the needed
/// APIs to map virtual to physical addresses to these pages. For more
/// information on how EPT page tables work, please see the Intel SDM. This
/// implementation attempts to map directly to the SDM text.
///
class EXPORT_MEMORY_MANAGER mmap
{

public:

    using phys_addr_t = uintptr_t;                      ///< Phys Address Type (as Int)
    using virt_addr_t = uintptr_t;                      ///< Virt Address Type (as Ptr)
    using size_type = size_t;                           ///< Size Type
    using entry_type = uintptr_t;                       ///< Entry Type
    using index_type = std::ptrdiff_t;                  ///< Index Type

    // @cond

    enum class attr_type {
        none,
        read_only,
        write_only,
        execute_only,
        read_write,
        read_execute,
        read_write_execute
    };

    enum class memory_type {
        uncacheable = 0,
        write_combining = 1,
        write_through = 4,
        write_protected = 5,
        write_back = 6
    };

    struct pair {
        gsl::span<virt_addr_t> virt_addr{};
        phys_addr_t phys_addr{};
    };

    // @endcond

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    mmap() :
        m_pml4{allocate_span(::intel_x64::ept::pml4::num_entries), 0}
    { }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~mmap()
    {
        for (auto pml4i = 0; pml4i < ::intel_x64::ept::pml4::num_entries; pml4i++) {
            auto &entry = m_pml4.virt_addr.at(pml4i);

            if (entry == 0) {
                continue;
            }

            this->clear_pdpt(pml4i);
        }

        free_page(m_pml4.virt_addr.data());
    }

    /// EPTP
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the value that should be written into EPTP
    ///
    uintptr_t eptp()
    {
        if (m_pml4.phys_addr == 0) {
            m_pml4.phys_addr = g_mm->virtptr_to_physint(m_pml4.virt_addr.data());
        }

        return m_pml4.phys_addr;
    }

    /// Map 1g Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_1g(
        virt_addr_t *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        return this->map_pdpte(virt_addr, phys_addr, attr, cache);
    }

    /// Map 1g Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_1g(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_1g(reinterpret_cast<virt_addr_t *>(virt_addr), phys_addr, attr, cache);
    }

    /// Map 2m Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_2m(
        virt_addr_t *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));

        return this->map_pde(virt_addr, phys_addr, attr, cache);
    }

    /// Map 2m Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_2m(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_2m(reinterpret_cast<virt_addr_t *>(virt_addr), phys_addr, attr, cache);
    }

    /// Map 4k Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_4k(
        virt_addr_t *virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        this->map_pt(::intel_x64::ept::pd::index(virt_addr));

        return this->map_pte(virt_addr, phys_addr, attr, cache);
    }

    /// Map 4k Virt Address to Phys Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the entry that performs the map
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    entry_type &
    map_4k(
        virt_addr_t virt_addr,
        phys_addr_t phys_addr,
        attr_type attr = attr_type::read_write_execute,
        memory_type cache = memory_type::write_back)
    {
        return map_4k(reinterpret_cast<virt_addr_t *>(virt_addr), phys_addr, attr, cache);
    }

    /// Unmap Virtual Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void
    unmap(virt_addr_t *virt_addr)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (pdpte == 0) {
            return;
        }

        if (::intel_x64::ept::pdpt::entry::ps::is_enabled(pdpte)) {
            pdpte = 0;
            return;
        }

        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (pde == 0) {
            return;
        }

        if (::intel_x64::ept::pd::entry::ps::is_enabled(pde)) {
            pde = 0;
            return;
        }

        this->map_pt(::intel_x64::ept::pd::index(virt_addr));
        m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr)) = 0;
    }

    /// Unmap Virtual Address
    ///
    /// @note This function does not release any page tables associated with
    ///     mapping being unmapped by this function. As a result, if you need
    ///     to cleanup memory, or reconfigure a mapping (e.g. 2m to 4k), you
    ///     must also execute release()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void unmap(virt_addr_t virt_addr)
    { unmap(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void
    release(virt_addr_t *virt_addr)
    {
        if (this->release_pdpte(virt_addr)) {
            m_pml4.virt_addr.at(::intel_x64::ept::pml4::index(virt_addr)) = 0;
        }
    }

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to unmap
    ///
    void release(virt_addr_t virt_addr)
    { release(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Virtual Address to Entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return returns entry for the map
    ///
    entry_type &
    entry(virt_addr_t *virt_addr)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        auto &pdpte = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("entry: pdpte not mapped");
        }

        if (::intel_x64::ept::pdpt::entry::ps::is_enabled(pdpte)) {
            return pdpte;
        }

        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        auto &pde = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("entry: pde not mapped");
        }

        if (::intel_x64::ept::pd::entry::ps::is_enabled(pde)) {
            return pde;
        }

        this->map_pt(::intel_x64::ept::pd::index(virt_addr));
        auto &pte = m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("entry: pte not mapped");
        }

        return pte;
    }

    /// Virtual Address to Entry
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return returns entry for the map
    ///
    entry_type &entry(virt_addr_t virt_addr)
    { return entry(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    phys_addr_t
    virt_to_phys(virt_addr_t *virt_addr)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        auto pdpte = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("virt_to_phys: pdpte not mapped");
        }

        if (::intel_x64::ept::pdpt::entry::ps::is_enabled(pdpte)) {
            return ::intel_x64::ept::pdpt::entry::phys_addr::get(pdpte);
        }

        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        auto pde = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("virt_to_phys: pde not mapped");
        }

        if (::intel_x64::ept::pd::entry::ps::is_enabled(pde)) {
            return ::intel_x64::ept::pd::entry::phys_addr::get(pde);
        }

        this->map_pt(::intel_x64::ept::pd::index(virt_addr));
        auto pte = m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("virt_to_phys: pte not mapped");
        }

        return ::intel_x64::ept::pt::entry::phys_addr::get(pte);
    }

    /// Virtual Address to Physical Address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to be converted
    /// @return Returns the phys_addr for the map
    ///
    phys_addr_t virt_to_phys(virt_addr_t virt_addr)
    { return virt_to_phys(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Virtual Address to From
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns page size of the mapping (i.e. from)
    ///
    auto
    from(virt_addr_t *virt_addr)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        auto pdpte = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (pdpte == 0) {
            throw std::runtime_error("from: pdpte not mapped");
        }

        if (::intel_x64::ept::pdpt::entry::ps::is_enabled(pdpte)) {
            return ::intel_x64::ept::pdpt::from;
        }

        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        auto pde = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (pde == 0) {
            throw std::runtime_error("from: pde not mapped");
        }

        if (::intel_x64::ept::pd::entry::ps::is_enabled(pde)) {
            return ::intel_x64::ept::pd::from;
        }

        this->map_pt(::intel_x64::ept::pd::index(virt_addr));
        auto pte = m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr));

        if (pte == 0) {
            throw std::runtime_error("from: pte not mapped");
        }

        return ::intel_x64::ept::pt::from;
    }

    /// Virtual Address to From
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns page size of the mapping (i.e. from)
    ///
    auto from(virt_addr_t virt_addr)
    { return from(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Is 1g
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 1g page,
    ///     false otherwise
    ///
    inline auto is_1g(virt_addr_t *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pdpt::from; }

    /// Is 1g
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 1g page,
    ///     false otherwise
    ///
    inline auto is_1g(virt_addr_t virt_addr)
    { return is_1g(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Is 2m
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 2m page,
    ///     false otherwise
    ///
    inline auto is_2m(virt_addr_t *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pd::from; }

    /// Is 2m
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 2m page,
    ///     false otherwise
    ///
    inline auto is_2m(virt_addr_t virt_addr)
    { return is_2m(reinterpret_cast<virt_addr_t *>(virt_addr)); }

    /// Is 4k
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 4k page,
    ///     false otherwise
    ///
    inline auto is_4k(virt_addr_t *virt_addr)
    { return from(virt_addr) == ::intel_x64::ept::pt::from; }

    /// Is 4k
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to test
    /// @return returns true if the virtual address was mapped as 4k page,
    ///     false otherwise
    ///
    inline auto is_4k(virt_addr_t virt_addr)
    { return is_4k(reinterpret_cast<virt_addr_t *>(virt_addr)); }

private:

    gsl::span<virt_addr_t>
    allocate_span(size_type num_entries)
    {
        return
            gsl::make_span(
                static_cast<virt_addr_t *>(alloc_page()),
                num_entries
            );
    }

    pair
    allocate(size_type num_entries)
    {
        auto span =
            gsl::make_span(
                static_cast<virt_addr_t *>(alloc_page()),
                num_entries
            );

        pair ptrs = {
            span,
            g_mm->virtptr_to_physint(
                span.data()
            )
        };

        return ptrs;
    }

    void
    free(const gsl::span<virt_addr_t> &virt_addr)
    { free_page(virt_addr.data()); }

private:

    pair
    phys_to_pair(phys_addr_t phys_addr, size_type num_entries)
    {
        auto virt_addr =
            static_cast<virt_addr_t *>(
                g_mm->physint_to_virtptr(phys_addr)
            );

        return {
            gsl::make_span<virt_addr_t>(virt_addr, num_entries),
            phys_addr
        };
    }

    void
    map_pdpt(index_type pml4i)
    {
        auto &entry = m_pml4.virt_addr.at(pml4i);

        if (entry != 0) {
            auto phys_addr = ::intel_x64::ept::pml4::entry::phys_addr::get(entry);

            if (m_pdpt.phys_addr == phys_addr) {
                return;
            }

            m_pdpt = phys_to_pair(phys_addr, ::intel_x64::ept::pdpt::num_entries);
            return;
        }

        m_pdpt = this->allocate(::intel_x64::ept::pdpt::num_entries);

        ::intel_x64::ept::pml4::entry::phys_addr::set(entry, m_pdpt.phys_addr);
        ::intel_x64::ept::pml4::entry::read_access::enable(entry);
        ::intel_x64::ept::pml4::entry::write_access::enable(entry);
        ::intel_x64::ept::pml4::entry::execute_access::enable(entry);
    }

    void
    map_pd(index_type pdpti)
    {
        auto &entry = m_pdpt.virt_addr.at(pdpti);

        if (entry != 0) {
            auto phys_addr = ::intel_x64::ept::pdpt::entry::phys_addr::get(entry);

            if (m_pd.phys_addr == phys_addr) {
                return;
            }

            m_pd = phys_to_pair(phys_addr, ::intel_x64::ept::pd::num_entries);
            return;
        }

        m_pd = this->allocate(::intel_x64::ept::pd::num_entries);

        ::intel_x64::ept::pdpt::entry::phys_addr::set(entry, m_pd.phys_addr);
        ::intel_x64::ept::pdpt::entry::read_access::enable(entry);
        ::intel_x64::ept::pdpt::entry::write_access::enable(entry);
        ::intel_x64::ept::pdpt::entry::execute_access::enable(entry);
    }

    void
    map_pt(index_type pdi)
    {
        auto &entry = m_pd.virt_addr.at(pdi);

        if (entry != 0) {
            auto phys_addr = ::intel_x64::ept::pd::entry::phys_addr::get(entry);

            if (m_pt.phys_addr == phys_addr) {
                return;
            }

            m_pt = phys_to_pair(phys_addr, ::intel_x64::ept::pt::num_entries);
            return;
        }

        m_pt = this->allocate(::intel_x64::ept::pt::num_entries);

        ::intel_x64::ept::pd::entry::phys_addr::set(entry, m_pt.phys_addr);
        ::intel_x64::ept::pd::entry::read_access::enable(entry);
        ::intel_x64::ept::pd::entry::write_access::enable(entry);
        ::intel_x64::ept::pd::entry::execute_access::enable(entry);
    }

    void
    clear_pdpt(index_type pml4i)
    {
        this->map_pdpt(pml4i);

        for (auto pdpti = 0; pdpti < ::intel_x64::ept::pdpt::num_entries; pdpti++) {
            auto &entry = m_pdpt.virt_addr.at(pdpti);

            if (entry == 0) {
                continue;
            }

            if (::intel_x64::ept::pdpt::entry::ps::is_disabled(entry)) {
                this->clear_pd(pdpti);
            }

            entry = 0;
        }

        this->free(m_pdpt.virt_addr);
        m_pdpt = {};
    }

    void
    clear_pd(index_type pdpti)
    {
        this->map_pd(pdpti);

        for (auto pdi = 0; pdi < ::intel_x64::ept::pd::num_entries; pdi++) {
            auto &entry = m_pd.virt_addr.at(pdi);

            if (entry == 0) {
                continue;
            }

            if (::intel_x64::ept::pd::entry::ps::is_disabled(entry)) {
                this->clear_pt(pdi);
            }

            entry = 0;
        }

        this->free(m_pd.virt_addr);
        m_pd = {};
    }

    void
    clear_pt(index_type pdi)
    {
        this->map_pt(pdi);

        this->free(m_pt.virt_addr);
        m_pt = {};
    }

    entry_type &
    map_pdpte(
        virt_addr_t *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        auto &entry = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pdpte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::intel_x64::ept::pdpt::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                ::intel_x64::ept::pdpt::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                ::intel_x64::ept::pdpt::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                ::intel_x64::ept::pdpt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                ::intel_x64::ept::pdpt::entry::read_access::enable(entry);
                ::intel_x64::ept::pdpt::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                ::intel_x64::ept::pdpt::entry::read_access::enable(entry);
                ::intel_x64::ept::pdpt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                ::intel_x64::ept::pdpt::entry::read_access::enable(entry);
                ::intel_x64::ept::pdpt::entry::write_access::enable(entry);
                ::intel_x64::ept::pdpt::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                ::intel_x64::ept::pdpt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pdpt::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                ::intel_x64::ept::pdpt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pdpt::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                ::intel_x64::ept::pdpt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pdpt::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                ::intel_x64::ept::pdpt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pdpt::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                ::intel_x64::ept::pdpt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pdpt::entry::memory_type::write_back
                );
                break;
        };

        ::intel_x64::ept::pdpt::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pde(
        virt_addr_t *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        auto &entry = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pde: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::intel_x64::ept::pd::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                ::intel_x64::ept::pd::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                ::intel_x64::ept::pd::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                ::intel_x64::ept::pd::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                ::intel_x64::ept::pd::entry::read_access::enable(entry);
                ::intel_x64::ept::pd::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                ::intel_x64::ept::pd::entry::read_access::enable(entry);
                ::intel_x64::ept::pd::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                ::intel_x64::ept::pd::entry::read_access::enable(entry);
                ::intel_x64::ept::pd::entry::write_access::enable(entry);
                ::intel_x64::ept::pd::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                ::intel_x64::ept::pd::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pd::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                ::intel_x64::ept::pd::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pd::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                ::intel_x64::ept::pd::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pd::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                ::intel_x64::ept::pd::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pd::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                ::intel_x64::ept::pd::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pd::entry::memory_type::write_back
                );
                break;
        };

        ::intel_x64::ept::pd::entry::ps::enable(entry);
        return entry;
    }

    entry_type &
    map_pte(
        virt_addr_t *virt_addr, phys_addr_t phys_addr,
        attr_type attr, memory_type cache)
    {
        auto &entry = m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr));

        if (entry != 0) {
            throw std::runtime_error(
                "map_pte: map failed, virt / phys map already exists: " +
                bfn::to_string(phys_addr, 16)
            );
        }

        ::intel_x64::ept::pt::entry::phys_addr::set(entry, phys_addr);

        switch (attr) {
            case attr_type::none:
                break;

            case attr_type::read_only:
                ::intel_x64::ept::pt::entry::read_access::enable(entry);
                break;

            case attr_type::write_only:
                ::intel_x64::ept::pt::entry::write_access::enable(entry);
                break;

            case attr_type::execute_only:
                ::intel_x64::ept::pt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write:
                ::intel_x64::ept::pt::entry::read_access::enable(entry);
                ::intel_x64::ept::pt::entry::write_access::enable(entry);
                break;

            case attr_type::read_execute:
                ::intel_x64::ept::pt::entry::read_access::enable(entry);
                ::intel_x64::ept::pt::entry::execute_access::enable(entry);
                break;

            case attr_type::read_write_execute:
                ::intel_x64::ept::pt::entry::read_access::enable(entry);
                ::intel_x64::ept::pt::entry::write_access::enable(entry);
                ::intel_x64::ept::pt::entry::execute_access::enable(entry);
                break;
        };

        switch (cache) {
            case memory_type::uncacheable:
                ::intel_x64::ept::pt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pt::entry::memory_type::uncacheable
                );
                break;

            case memory_type::write_combining:
                ::intel_x64::ept::pt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pt::entry::memory_type::write_combining
                );
                break;

            case memory_type::write_through:
                ::intel_x64::ept::pt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pt::entry::memory_type::write_through
                );
                break;

            case memory_type::write_protected:
                ::intel_x64::ept::pt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pt::entry::memory_type::write_protected
                );
                break;

            case memory_type::write_back:
                ::intel_x64::ept::pt::entry::memory_type::set(
                    entry,
                    ::intel_x64::ept::pt::entry::memory_type::write_back
                );
                break;
        };

        return entry;
    }

    bool
    release_pdpte(virt_addr_t *virt_addr)
    {
        this->map_pdpt(::intel_x64::ept::pml4::index(virt_addr));
        auto &entry = m_pdpt.virt_addr.at(::intel_x64::ept::pdpt::index(virt_addr));

        if (::intel_x64::ept::pdpt::entry::ps::is_disabled(entry)) {
            if (!this->release_pde(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdpti = 0; pdpti < ::intel_x64::ept::pdpt::num_entries; pdpti++) {
            if (m_pdpt.virt_addr.at(pdpti) != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pdpt.virt_addr);
            return true;
        }

        return false;
    }

    bool
    release_pde(virt_addr_t *virt_addr)
    {
        this->map_pd(::intel_x64::ept::pdpt::index(virt_addr));
        auto &entry = m_pd.virt_addr.at(::intel_x64::ept::pd::index(virt_addr));

        if (::intel_x64::ept::pd::entry::ps::is_disabled(entry)) {
            if (!this->release_pte(virt_addr)) {
                return false;
            }
        }

        entry = 0;

        auto empty = true;
        for (auto pdi = 0; pdi < ::intel_x64::ept::pd::num_entries; pdi++) {
            if (m_pd.virt_addr.at(pdi) != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pd.virt_addr);
            return true;
        }

        return false;
    }

    bool
    release_pte(virt_addr_t *virt_addr)
    {
        this->map_pt(::intel_x64::ept::pd::index(virt_addr));
        m_pt.virt_addr.at(::intel_x64::ept::pt::index(virt_addr)) = 0;

        auto empty = true;
        for (auto pti = 0; pti < ::intel_x64::ept::pt::num_entries; pti++) {
            if (m_pt.virt_addr.at(pti) != 0) {
                empty = false;
            }
        }

        if (empty) {
            this->free(m_pt.virt_addr);
            return true;
        }

        return false;
    }

private:

    pair m_pml4;
    pair m_pdpt;
    pair m_pd;
    pair m_pt;

public:

    /// @cond

    mmap(mmap &&) = default;
    mmap &operator=(mmap &&) = default;

    mmap(const mmap &) = delete;
    mmap &operator=(const mmap &) = delete;

    /// @endcond
};

}
}
}

#endif
