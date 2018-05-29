//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef PHYS_MTRR_INTEL_X64_EAPIS_H
#define PHYS_MTRR_INTEL_X64_EAPIS_H

#include <arch/intel_x64/mtrr.h>
#include "../../../hve/arch/intel_x64/mtrr.h"
#include "../../../hve/arch/intel_x64/base.h"

namespace eapis
{
namespace intel_x64
{

/// MTRRs
///
/// MTRRs are typically set by the BIOS. There is also an ACPI/e820 table
/// that describes the range types (could be useful for emulation).
///
/// There are two types of ranges that MTRRs specify: fixed and variable.
/// The first 1MB of physical memory is specified by the 11 fixed-range MTRRs
/// (i.e. 11 MSRs), with each MTRR divided into eight, 1-byte sub-ranges:
///
/// [0x00000, 0x7FFFF] (1 MSR * 8 sub-ranges * 64KB each == 512KB)
/// [0x80000, 0xBFFFF] (2 MSR * 8 sub-ranges * 16KB each == 256KB)
/// [0xC0000, 0xFFFFF] (8 MSR * 8 sub-ranges * 4KB  each == 256KB)
///
/// The number of variable ranges is IA32_MTRRCAP[7:0], and each range
/// is specified with two MSRs; one that describes the base and memory type,
/// and another that helps determine the range size.

/// Physical MTRR interface
///
/// This class provides a light-weight abstration over the platforms
/// memory type range registers (MTRRs).
///
class EXPORT_EAPIS_HVE phys_mtrr
{
public:

    /// There are 88 fixed ranges total
    static constexpr uint64_t s_fixed_count = 88U;

    /// The total size over all fixed range MTRRs is 1MB. The base is
    /// defined by the manual as 0.
    static constexpr uint64_t s_fixed_size = 0x100000U; // First 1MB

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    phys_mtrr();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~phys_mtrr() = default;

    /// Default type
    ///
    /// @return the default memory type.
    ///
    uint64_t default_mem_type() const;

    /// Memory type
    ///
    /// @param addr the address to lookup
    /// @return the memory type for the given address.
    ///
    uint64_t mem_type(uintptr_t addr) const;

    /// Range list
    ///
    /// Return a set of ranges, each with one memory type, ordered
    /// by ascending address starting from the given @param base and
    /// extending to @param base + @param size - 1.
    ///
    /// @note each produced range is a multple of 4KB > 0
    /// @note the guarantee of one type per range does not imply that the range
    /// only has one type as programmed by the physical MTRRs. It is possible that
    /// there are several types mapped over the range. In this case, the smallest
    /// range with multiple types will be computed, and the type returned for that
    /// range will be the same as described by the precedence rules in
    /// section 11.11.4.1. This overlap seems unlikely in practice.
    ///
    /// @param[in] base the base of the range
    /// @param[in] size the number of bytes in the range
    /// @param[in,out] list the list of ranges
    ///
    void range_list(
        const uintptr_t base,
        const uint64_t size,
        std::vector<mtrr::range> &list) const;

    /// Enabled
    ///
    /// @return true iff the 'e' bit in IA32_MTRR_DEF_TYPE is 1
    /// @return true does not imply that the fixed range MTRRs are enabled
    ///
    bool enabled() const;

    /// Variable count
    ///
    /// @return the number of variable ranges
    ///
    uint64_t variable_count() const;

    /// Fixed count
    ///
    /// @return the number of fixed ranges
    ///
    uint64_t fixed_count() const;

    /// Variable supported
    ///
    /// @return true iff at least one variable MTRR is supported
    ///
    bool variable_supported() const;

    /// Fixed supported
    ///
    /// @return true iff fixed range MTRRs (IA32_MTRR_FIX64k_00000 through
    /// IA32_MTRR_FIX4K_0F8000) are supported
    ///
    bool fixed_supported() const;

    /// Fixed enabled
    ///
    /// @return true iff fixed-range MTRRs are enabled
    ///
    bool fixed_enabled() const;

    /// WC supported
    ///
    /// @return true iff the write-combining memory type is supported
    ///
    bool wc_supported() const;

    /// SMRR supported
    ///
    /// @return true iff the system-management range register (SMRR) interface
    /// is supported
    ///
    bool smrr_supported() const;

private:

    void init_variable_ranges();
    void init_fixed_ranges();
    void init_fixed_types();
    void print_fixed_ranges(uint64_t level) const;
    void print_variable_ranges(uint64_t level) const;

    std::array<uint64_t, 256U> m_fixed_range = {0U};
    std::array<uint64_t, s_fixed_count> m_fixed_type = {0U};
    std::vector<eapis::intel_x64::mtrr::variable_range> m_variable_range;

    uint64_t m_pas; // Physical address size
    uint64_t m_cap; // MTRR capability MSR
    uint64_t m_def; // MTRR default type MSR

public:

    // @cond

    phys_mtrr(phys_mtrr &&) = default;
    phys_mtrr &operator=(phys_mtrr &&) = default;

    phys_mtrr(const phys_mtrr &) = delete;
    phys_mtrr &operator=(const phys_mtrr &) = delete;

    /// @endcond
};

}
}

#endif
