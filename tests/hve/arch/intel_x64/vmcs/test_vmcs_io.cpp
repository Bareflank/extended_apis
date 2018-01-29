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

#include <test_support.h>
#include <catch/catch.hpp>

using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("vmcs_intel_x64_eapis_io: enable io bitmaps")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->enable_io_bitmaps();

    CHECK(vmcs->m_io_bitmapa != nullptr);
    CHECK(vmcs->m_io_bitmapb != nullptr);
    CHECK(vmcs->m_io_bitmapa_view.data() != nullptr);
    CHECK(vmcs->m_io_bitmapa_view.size() == static_cast<std::ptrdiff_t>(x64::page_size));
    CHECK(vmcs->m_io_bitmapb_view.data() != nullptr);
    CHECK(vmcs->m_io_bitmapb_view.size() == static_cast<std::ptrdiff_t>(x64::page_size));
    CHECK(address_of_io_bitmap_a::get() != 0);
    CHECK(address_of_io_bitmap_b::get() != 0);
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
}

TEST_CASE("vmcs_intel_x64_eapis_io: disable io bitmaps")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->disable_io_bitmaps();

    CHECK(vmcs->m_io_bitmapa == nullptr);
    CHECK(vmcs->m_io_bitmapb == nullptr);
    CHECK(vmcs->m_io_bitmapa_view.data() == nullptr);
    CHECK(vmcs->m_io_bitmapa_view.empty());
    CHECK(vmcs->m_io_bitmapb_view.data() == nullptr);
    CHECK(vmcs->m_io_bitmapb_view.empty());
    CHECK(address_of_io_bitmap_a::get() == 0);
    CHECK(address_of_io_bitmap_b::get() == 0);
    CHECK(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled());
}

TEST_CASE("vmcs_intel_x64_eapis_io: trap on io access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_io_access(0x42));

    vmcs->enable_io_bitmaps();
    vmcs->trap_on_io_access(0x42);
    vmcs->trap_on_io_access(0x8042);

    CHECK(vmcs->m_io_bitmapa_view[8] == 0x4);
    CHECK(vmcs->m_io_bitmapb_view[8] == 0x4);
}

TEST_CASE("vmcs_intel_x64_eapis_io: trap on all io accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_all_io_accesses());

    vmcs->enable_io_bitmaps();
    vmcs->trap_on_all_io_accesses();

    auto all_seta = 0xFF;
    for (auto val : vmcs->m_io_bitmapa_view) {
        all_seta &= val;
    }

    CHECK(all_seta == 0xFF);

    auto all_setb = 0xFF;
    for (auto val : vmcs->m_io_bitmapb_view) {
        all_setb &= val;
    }

    CHECK(all_setb == 0xFF);
}

TEST_CASE("vmcs_intel_x64_eapis_io: pass through io access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_io_access(0x42));

    vmcs->enable_io_bitmaps();
    vmcs->trap_on_all_io_accesses();
    vmcs->pass_through_io_access(0x42);
    vmcs->pass_through_io_access(0x8042);

    CHECK(vmcs->m_io_bitmapa_view[8] == 0xFB);
    CHECK(vmcs->m_io_bitmapb_view[8] == 0xFB);
}

TEST_CASE("vmcs_intel_x64_eapis_io: pass through all io accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_all_io_accesses());

    vmcs->enable_io_bitmaps();
    vmcs->pass_through_all_io_accesses();

    auto all_seta = 0x0;
    for (auto val : vmcs->m_io_bitmapa_view) {
        all_seta |= val;
    }

    CHECK(all_seta == 0x0);

    auto all_setb = 0x0;
    for (auto val : vmcs->m_io_bitmapb_view) {
        all_setb |= val;
    }

    CHECK(all_setb == 0x0);
}

TEST_CASE("vmcs_intel_x64_eapis_io: whitelist io access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->whitelist_io_access({0x42, 0x8042}));

    vmcs->enable_io_bitmaps();
    vmcs->whitelist_io_access({0x42, 0x8042});
    CHECK(vmcs->m_io_bitmapa_view[8] == 0xFB);
    CHECK(vmcs->m_io_bitmapb_view[8] == 0xFB);
}

TEST_CASE("vmcs_intel_x64_eapis_io: blacklist io access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->blacklist_io_access({0x42, 0x8042}));

    vmcs->enable_io_bitmaps();
    vmcs->blacklist_io_access({0x42, 0x8042});
    CHECK(vmcs->m_io_bitmapa_view[8] == 0x4);
    CHECK(vmcs->m_io_bitmapb_view[8] == 0x4);
}

#endif
