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

//#include <arch/intel_x64/mtrr.h>
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
    /// The returned value references the list of mtrr::ranges that
    /// are sorted by base address. The sequence is "contiguous"
    /// with range[i + 1].base == (range[i].base + range[i].size).
    /// Each element contains the memory type of the range it represents.
    ///
    /// @return the system's memory-type range list
    ///
    const std::vector<mtrr::range> *range_list() const;

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

    void parse_fixed_types();
    void parse_fixed_mtrrs();
    void parse_variable_mtrrs();

    void setup_range_list();
    void setup_fixed_range_list();
    void setup_variable_range_list();

    void print_fixed_ranges(uint64_t level) const;
    void print_variable_ranges(uint64_t level) const;
    void print_range_list(uint64_t level) const;

    std::array<uint8_t, 256U> m_fixed_range = {0U};
    std::array<uint8_t, intel_x64::mtrr::fixed_count> m_fixed_type = {0U};
    std::vector<intel_x64::mtrr::variable_range> m_variable_range;
    std::vector<intel_x64::mtrr::range> m_range_list;

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
