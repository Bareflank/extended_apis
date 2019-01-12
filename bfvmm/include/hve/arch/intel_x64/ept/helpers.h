//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef EPT_HELPERS_INTEL_X64_H
#define EPT_HELPERS_INTEL_X64_H

#include "mmap.h"
#include "../mtrrs.h"

namespace eapis::intel_x64::ept
{

//--------------------------------------------------------------------------
// Free
//--------------------------------------------------------------------------

/// Identity Map with 1g Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.map_1g(gpa, gpa, attr, cache);
    }
}

/// Identity Map with 2m Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.map_2m(gpa, gpa, attr, cache);
    }
}

/// Identity Map with 4k Granularity
///
/// Adds a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.map_4k(gpa, gpa, attr, cache);
    }
}

/// Identity Unmap with 1g Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Unmap with 2m Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Unmap with 4k Granularity
///
/// Unmaps a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_unmap_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.unmap(gpa);
    }
}

/// Identity Release with 1g Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 1g maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_1g(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pdpt::from) == 0);
    expects(bfn::lower(eaddr, pdpt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pdpt::page_size) {
        map.release(gpa);
    }
}

/// Identity Release with 2m Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 2m maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_2m(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pd::page_size) {
        map.release(gpa);
    }
}

/// Identity Release with 4k Granularity
///
/// Releases a 1:1 map from the starting address to the ending address
/// using 4k maps.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
///
inline void
identity_release_4k(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(saddr, pt::from) == 0);
    expects(bfn::lower(eaddr, pt::from) == 0);

    for (auto gpa = saddr; gpa < eaddr; gpa += pt::page_size) {
        map.release(gpa);
    }
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_1g_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    ept::identity_map_2m(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 1g to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_1g_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_1g(addr));

    map.unmap(addr);

    ept::identity_map_4k(
        map, addr, addr + pdpt::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_2m_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_2m(addr));

    identity_release_2m(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 1g.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_4k_to_1g(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pdpt::from) == 0);
    expects(map.is_4k(addr));

    identity_release_4k(
        map, addr, addr + pdpt::page_size
    );

    map.map_1g(addr, addr, attr, cache);
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 2m to 4k.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_2m_to_4k(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_2m(addr));

    map.unmap(addr);

    ept::identity_map_4k(
        map, addr, addr + pd::page_size, attr, cache
    );
}

/// Convert Identity Map Granularity
///
/// Converts the granularity of a map from 4k to 2m.
///
/// @param map the map to apply the identity map too
/// @param addr the address to convert
/// @param attr the memory attributes to apply to the map
/// @param cache the memory type to apply to the map
///
inline void
identity_map_convert_4k_to_2m(
    mmap &map,
    mmap::phys_addr_t addr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute,
    mmap::memory_type cache = mmap::memory_type::write_back)
{
    using namespace ::intel_x64::ept;

    expects(bfn::lower(addr, pd::from) == 0);
    expects(map.is_4k(addr));

    ept::identity_release_4k(
        map, addr, addr + pd::page_size
    );

    map.map_2m(addr, addr, attr, cache);
}

//--------------------------------------------------------------------------
// Checked
//--------------------------------------------------------------------------

/// Identity Map
///
/// Adds a 1:1 map from the starting address to the ending address.
/// This version incorporates the MTRRs, ensuring the cache type is set up
/// properly in EPT. 2m granularity is always used unless the MTRRs define a
/// range that is not on a 2m boundry in which case 4k is used. Regular RAM
/// is likely to be mapped using 2m regions.
///
/// Note that this version should ALWAYS be used when creating an EPT memory
/// map for the Host OS, as using EPT ignores the MTRRs which can cause
/// corruption on the host OS.
///
/// @param map the map to apply the identity map too
/// @param saddr the starting address for the map
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
///
inline void
identity_map(
    mmap &map,
    mmap::phys_addr_t saddr,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute)
{
    using namespace ::intel_x64::ept;
    auto range = g_mtrrs->ranges().begin();

    expects(g_mtrrs->size() != 0);
    expects(bfn::lower(saddr, pd::from) == 0);
    expects(bfn::lower(eaddr, pd::from) == 0);

    while (saddr < eaddr) {
        while (!range->contains(saddr)) {
            range++;
        }

        if (bfn::lower(saddr, pd::from) == 0 &&
            std::min(range->distance(saddr), eaddr - saddr) >= pd::page_size
           ) {
            map.map_2m(saddr, saddr, attr, range->type);
            saddr += pd::page_size;
        }
        else {
            map.map_4k(saddr, saddr, attr, range->type);
            saddr += pt::page_size;
        }
    }
}

/// Identity Map
///
/// Adds a 1:1 map from 0 to the ending address.
/// This version incorporates the MTRRs, ensuring the cache type is set up
/// properly in EPT. 2m granularity is always used unless the MTRRs define a
/// range that is not on a 2m boundry in which case 4k is used. Regular RAM
/// is likely to be mapped using 2m regions.
///
/// Note that this version should ALWAYS be used when creating an EPT memory
/// map for the Host OS, as using EPT ignores the MTRRs which can cause
/// corruption on the host OS.
///
/// @param map the map to apply the identity map too
/// @param eaddr the ending address for the map
/// @param attr the memory attributes to apply to the map
///
inline void
identity_map(
    mmap &map,
    mmap::phys_addr_t eaddr,
    mmap::attr_type attr = mmap::attr_type::read_write_execute)
{ identity_map(map, 0, eaddr, attr); }

}

#endif
