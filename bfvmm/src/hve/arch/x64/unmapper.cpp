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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <hve/arch/x64/unmapper.h>
#include <bfvmm/memory_manager/arch/x64/cr3.h>

namespace eapis::x64
{

void
unmapper::operator()(void *p) const
{
    bfignored(p);
    using namespace ::x64::pt;

    /// Note:
    ///
    /// For now, we do not have a map_gva function that is above 4k, so we
    /// only need to loop with 4k granularity. All of the map_gpa functions
    /// only need to unmap once, so they will work as well. At some point,
    /// we should add a map_gva functions that is above 4k. When this is
    /// done, we will likely have to track the granularity so that we know
    /// what pages need to be unmapped specifically.
    ///

    for (auto hva = m_hva; hva < m_hva + m_len; hva += page_size) {
        g_cr3->unmap(hva);
        ::x64::tlb::invlpg(hva);
    }

    g_mm->free_map(reinterpret_cast<void *>(m_hva));
}

}
