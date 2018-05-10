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
#include <hve/arch/intel_x64/virt_ioapic.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace ioapic = ::intel_x64::ioapic;

TEST_CASE("virt_ioapic")
{
    auto virt = virt_ioapic();

    virt.select(ioapic::id::offset);
    CHECK(virt.read() == ioapic::id::default_val);

    virt.select(ioapic::ver::offset);
    CHECK(virt.read() == ioapic::ver::default_val);

    virt.select(ioapic::arb::offset);
    CHECK(virt.read() == ioapic::arb::default_val);

    for (ioapic::offset_t i = 3U; i < ioapic::rte_begin; ++i) {
        CHECK_THROWS(virt.select(i));
    }

    for (ioapic::offset_t i = ioapic::rte_begin; i < ioapic::rte_end; ++i) {
        CHECK_NOTHROW(virt.select(i));
        CHECK_NOTHROW(virt.read() == ioapic::rte::mask_bit::enable(0U));
        virt.write(0ULL);
        CHECK(ioapic::rte::mask_bit::is_disabled(virt.read()));
    }
}

}
}

#endif
