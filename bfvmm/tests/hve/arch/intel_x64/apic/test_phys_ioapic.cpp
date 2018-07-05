//
// Bareflank Extended APIs
//
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

#include <hve/arch/intel_x64/hve.h>
#include <arch/intel_x64/apic/ioapic.h>

#include <hve/arch/intel_x64/apic/phys_ioapic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

alignas(16) uint32_t
g_ioapic[0x40U] = {0U};
uintptr_t g_base = reinterpret_cast<uintptr_t>(g_ioapic);

namespace ioapic = ::intel_x64::ioapic;

TEST_CASE("phys_ioapic")
{
    auto ioapic = phys_ioapic(0xFEC00000U);
    CHECK(ioapic.base() == 0xFEC00000U);
    CHECK_NOTHROW(ioapic.relocate(g_base));
    CHECK_THROWS(ioapic.select(0xFFU));

    for (ioapic::offset_t i = 0U; i < ioapic::rte_end; ++i) {
        if (eapis::intel_x64::ioapic::is_writable(i)) {
            CHECK_NOTHROW(ioapic.select(i));
            CHECK_NOTHROW(ioapic.write(0xFFFFFFFFU));
            CHECK(eapis::intel_x64::ioapic::is_readable(i));
            CHECK_NOTHROW(ioapic.read() == 0xFFFFFFFFU);
            continue;
        }

        if (eapis::intel_x64::ioapic::is_read_only(i)) {
            CHECK_NOTHROW(ioapic.select(i));
            CHECK_THROWS(ioapic.write(0U));
            continue;
        }

        CHECK_FALSE(eapis::intel_x64::ioapic::exists(i));
    }
}

}
}

#endif
