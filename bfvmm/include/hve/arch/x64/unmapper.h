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

#ifndef UNMAPPER_X64_EAPIS_H
#define UNMAPPER_X64_EAPIS_H

#include <memory>
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis::x64
{

/// Unmapper
///
/// This class is used by the mapping functions to unmap previously mapped
/// memory. This unmapper adheres to the deleter concept for a
/// std::unique_ptr so that a std::unique_ptr can be used for mapping memory.
///
class unmapper
{
    uintptr_t m_hva{};
    std::size_t m_len{};

public:

    unmapper() = default;

    explicit unmapper(
        void *hva,
        std::size_t len
    ) :
        m_hva{reinterpret_cast<uintptr_t>(hva)},
        m_len{len}
    { }

    void operator()(void *p) const;
};

template<typename T>
using unique_map = std::unique_ptr<T, unmapper>;

}

#endif
