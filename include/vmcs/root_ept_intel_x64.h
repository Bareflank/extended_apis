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

#ifndef ROOT_EPT_INTEL_X64_H
#define ROOT_EPT_INTEL_X64_H

#include <gsl/gsl>

#include <mutex>
#include <vector>

#include <memory.h>
#include <vmcs/ept_intel_x64.h>
#include <vmcs/ept_attr_intel_x64.h>

/// Root Page Tables
///
/// The VMM has to have a set of page tables for itself to map in memory
/// for itself, but also from other guests. This class represents the root
/// page tables that the VMM will use.
///
/// Note that this class does not flush the TLB when modifications are made.
/// This needs to be done manually. In general, this class should not be used
/// directly, but instead mapping should be done via a unique_map_ptr_x64.
///
class root_ept_intel_x64
{
public:

    using pointer = void *;
    using integer_pointer = uintptr_t;
    using eptp_type = uint64_t;
    using attr_type = intel_x64::ept::memory_attr::attr_type;
    using size_type = size_t;
    using memory_descriptor_list = ept_intel_x64::memory_descriptor_list;

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    root_ept_intel_x64();

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~root_ept_intel_x64() = default;

    /// Extended Page Table Pointer
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the eptp value associated with this root
    ///     page table
    ///
    virtual eptp_type eptp();

    /// Map (1 Gigabyte)
    ///
    /// Maps 1 gigabyte of memory in the extended page tables given a guest
    /// physical address, the physical address and a set of attributes.
    ///
    /// @note: the user should ensure that this level of page granularity is
    ///     supported by hardware using intel_x64::msrs::ia32_vmx_ept_vpid_cap
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_1g(integer_pointer gpa, integer_pointer phys, attr_type attr)
    { this->map_page(gpa, phys, attr, intel_x64::ept::pdpt::size_bytes); }

    /// Map (2 Megabytes)
    ///
    /// Maps 2 megabytes of memory in the extended page tables given a guest
    /// physical address, the physical address and a set of attributes.
    ///
    /// @note: the user should ensure that this level of page granularity is
    ///     supported by hardware using intel_x64::msrs::ia32_vmx_ept_vpid_cap
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_2m(integer_pointer gpa, integer_pointer phys, attr_type attr)
    { this->map_page(gpa, phys, attr, intel_x64::ept::pd::size_bytes); }

    /// Map (4 Kilobytes)
    ///
    /// Maps 4 kilobytes of memory in the extended page tables given a guest
    /// physical address, the physical address and a set of attributes.
    ///
    /// @note: the user should ensure that this level of page granularity is
    ///     supported by hardware using intel_x64::msrs::ia32_vmx_ept_vpid_cap
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_4k(integer_pointer gpa, integer_pointer phys, attr_type attr)
    { this->map_page(gpa, phys, attr, intel_x64::ept::pt::size_bytes); }

    /// Unmap
    ///
    /// Unmaps memory in the extended page tables give a guest physical address.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to unmap
    ///
    void unmap(integer_pointer gpa) noexcept;

    /// Setup Identify Map (1g Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_1g(integer_pointer saddr, integer_pointer eaddr);

    /// Setup Identify Map (2m Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_2m(integer_pointer saddr, integer_pointer eaddr);

    /// Setup Identify Map (4k Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 1 gigabyte
    /// of memory granularity.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_identity_map_4k(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (1g Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_1g function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_1g(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (2m Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_2m function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_2m(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap Identify Map (4k Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_identity_map_4k function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_identity_map_4k(integer_pointer saddr, integer_pointer eaddr);

    /// Guest Physical Address To Extended Page Table Entry
    ///
    /// Locates the extended page table entry given a guest physical
    /// address. The entry is guaranteed not to be null (or an exception is
    /// thrown). This function can be used to access an EPTE, enabling the
    /// user to modify any part of the EPTE as desired. It should be noted
    /// that the extended page table owns the EPTE. Unmapping an EPTE
    /// invalidates the EPTE returned by this function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to lookup
    /// @return the resulting EPTE
    ///
    ept_entry_intel_x64 gpa_to_epte(integer_pointer gpa);

    /// Extended Page Table to Memory Descriptor List
    ///
    /// This function converts the internal page table tree structure into a
    /// linear, memory descriptor list. Page table entry information is not
    /// provide, only the page tables.
    /// pages.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return memory descriptor list
    ///
    memory_descriptor_list ept_to_mdl() const;

private:

    ept_entry_intel_x64 add_page(integer_pointer gpa, size_type size);

    void map_page(integer_pointer gpa, integer_pointer phys, attr_type attr, size_type size);
    void unmap_page(integer_pointer gpa) noexcept;

private:

    integer_pointer m_eptp;
    std::unique_ptr<ept_intel_x64> m_ept;

    mutable std::mutex m_mutex;

public:

    friend class eapis_ut;

    root_ept_intel_x64(root_ept_intel_x64 &&) = default;
    root_ept_intel_x64 &operator=(root_ept_intel_x64 &&) = default;

    root_ept_intel_x64(const root_ept_intel_x64 &) = delete;
    root_ept_intel_x64 &operator=(const root_ept_intel_x64 &) = delete;
};

#endif
