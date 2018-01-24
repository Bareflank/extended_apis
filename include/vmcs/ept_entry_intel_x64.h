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

#ifndef EPT_ENTRY_INTEL_X64_H
#define EPT_ENTRY_INTEL_X64_H

#include <bfgsl.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_VMCS
#ifdef SHARED_EAPIS_VMCS
#define EXPORT_EAPIS_VMCS EXPORT_SYM
#else
#define EXPORT_EAPIS_VMCS IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_VMCS
#endif

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

// *INDENT-OFF*
/// @cond

namespace intel_x64
{
namespace ept
{
    constexpr const auto num_entries = 512UL;
    constexpr const auto num_bytes = num_entries * sizeof(uintptr_t);

    template<class T, class F> auto index(const T virt, const F from)
    { return gsl::narrow_cast<std::ptrdiff_t>((virt & ((0x1FFULL) << from)) >> from); }

    // 512 GB per page entry
    namespace pml4
    {
        constexpr const auto from = 39U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x8000000000UL;
    }

    // 1 GB per page entry
    namespace pdpt
    {
        constexpr const auto from = 30U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x40000000UL;
    }

    // 2 MB per page entry
    namespace pd
    {
        constexpr const auto from = 21U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x200000UL;
    }

    // 4 KB per page entry
    namespace pt
    {
        constexpr const auto from = 12U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x1000UL;
    }

    namespace memory_type
    {
        constexpr const auto uc = 0;
        constexpr const auto wc = 1;
        constexpr const auto wt = 4;
        constexpr const auto wp = 5;
        constexpr const auto wb = 6;
    }
}
}

/// @endcond
// *INDENT-ON*

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

/// EPT Entry
///
/// Defines an entry in an EPT table.
///
class EXPORT_EAPIS_VMCS ept_entry_intel_x64
{
public:

    using pointer = uintptr_t *;            ///< Pointer type
    using integer_pointer = uintptr_t;      ///< Integer pointer type
    using memory_type_type = uint64_t;      ///< Memory type type
    using epte_value = uint64_t;

    /// Default Constructor
    ///
    /// @expects pte != nullptr
    /// @ensures none
    ///
    /// @param pte the pte that this page table entry encapsulates.
    ///
    ept_entry_intel_x64(gsl::not_null<pointer> pte) noexcept;

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~ept_entry_intel_x64() = default;

    /// EPTE pointer
    ///
    /// @expects none
    /// @ensures none
    ///
    pointer epte() const noexcept;

    /// Set EPTE pointer
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param val the pointer to replace m_epte with
    ///
    void set_epte(pointer val) noexcept;

    /// EPTE value
    ///
    /// @expects none
    /// @ensures none
    ///
    epte_value epte_val() const noexcept;

    /// Set EPTE pointer
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param val the value to write to EPTE pointer
    ///
    void set_epte_val(epte_value val) noexcept;

    /// Read Access
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if read access is allowed
    ///
    bool read_access() const noexcept;

    /// Set Read Access
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if read access is allowed, false otherwise
    ///
    void set_read_access(bool enabled) noexcept;

    /// Write Access
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if write access is allowed
    ///
    bool write_access() const noexcept;

    /// Set Write Access
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if write access is allowed, false otherwise
    ///
    void set_write_access(bool enabled) noexcept;

    /// Execute Access (All / Supervisor Mode)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if execute access is allowed
    ///
    bool execute_access() const noexcept;

    /// Set Execute Access (All / Supervisor Mode)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if execute access is allowed, false otherwise
    ///
    void set_execute_access(bool enabled) noexcept;

    /// Memory Type
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns memory type for this entry
    ///
    memory_type_type memory_type() const noexcept;

    /// Set Memory Type
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param val the memory type for this entry
    ///
    void set_memory_type(memory_type_type val) noexcept;

    /// Ignore PAT
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true the pat should be ignored, false otherwise
    ///
    bool ignore_pat() const noexcept;

    /// Set Ignore PAT
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the pat should be ignored disabled, false
    ///     otherwise
    ///
    void set_ignore_pat(bool enabled) noexcept;

    /// Entry Type
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this is an entry, false if this is a table
    ///
    bool entry_type() const noexcept;

    /// Set Entry Type
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if this is an entry, false if this is a table
    ///
    void set_entry_type(bool enabled) noexcept;

    /// Accessed
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry has been accessed, false otherwise
    ///
    bool accessed() const noexcept;

    /// Set Accessed
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry has been accessed, false
    ///     otherwise
    ///
    void set_accessed(bool enabled) noexcept;

    /// Dirty
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if this entry is dirty, false otherwise
    ///
    bool dirty() const noexcept;

    /// Set Dirty
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if the entry is dirty, false otherwise
    ///
    void set_dirty(bool enabled) noexcept;

    /// Execute Access (User Mode)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if execute access is allowed
    ///
    bool execute_access_user() const noexcept;

    /// Set Execute Access (User Mode)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if execute access is allowed, false otherwise
    ///
    void set_execute_access_user(bool enabled) noexcept;

    /// Physical Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return the physical address of the entry
    ///
    integer_pointer phys_addr() const noexcept;

    /// Set Physical Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param addr the physical address of the entry
    ///
    void set_phys_addr(integer_pointer addr) noexcept;

    /// Suppress VE
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return true if VE are suppressed, false otherwise
    ///
    bool suppress_ve() const noexcept;

    /// Set Suppress VE
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param enabled true if VE are suppressed, false otherwise
    ///
    void set_suppress_ve(bool enabled) noexcept;

    /// Trap On Access
    ///
    /// Disables read, write and execute access
    ///
    /// @expects none
    /// @ensures none
    ///
    void trap_on_access() noexcept;

    /// Pass Through Access
    ///
    /// Enables read, write and execute access
    ///
    /// @expects none
    /// @ensures none
    ///
    void pass_through_access() noexcept;

    /// Clear EPTE
    ///
    /// @expects none
    /// @ensures none
    ///
    void clear() noexcept;

private:

    pointer m_epte;                 ///< A pointer to the epte in memory

public:

    /// @cond

    ept_entry_intel_x64(ept_entry_intel_x64 &&) noexcept = default;
    ept_entry_intel_x64 &operator=(ept_entry_intel_x64 &&) noexcept = default;

    ept_entry_intel_x64(const ept_entry_intel_x64 &) = delete;
    ept_entry_intel_x64 &operator=(const ept_entry_intel_x64 &) = delete;

    /// @endcond
};

#endif
