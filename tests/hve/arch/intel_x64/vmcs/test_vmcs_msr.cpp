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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

#include "../../../../../include/support/arch/intel_x64/test_support.h"

namespace msr_bitmap_address = ::intel_x64::vmcs::address_of_msr_bitmap;

TEST_CASE("eapis_vmcs_msr: enable msr bitmap")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->enable_msr_bitmap();

    CHECK(vmcs->m_msr_bitmap != nullptr);
    CHECK(vmcs->m_msr_bitmap_view.data() != nullptr);
    CHECK(vmcs->m_msr_bitmap_view.size() == static_cast<std::ptrdiff_t>(x64::page_size));
    CHECK(msr_bitmap_address::get() != 0);
    CHECK(proc_ctls::use_msr_bitmap::is_enabled());
}

TEST_CASE("eapis_vmcs_msr: disable msr bitmap")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    vmcs->disable_msr_bitmap();

    CHECK(vmcs->m_msr_bitmap == nullptr);
    CHECK(vmcs->m_msr_bitmap_view.data() == nullptr);
    CHECK(vmcs->m_msr_bitmap_view.empty());
    CHECK(msr_bitmap_address::get() == 0);
    CHECK(proc_ctls::use_msr_bitmap::is_disabled());
}

TEST_CASE("eapis_vmcs_msr: trap on read msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_rdmsr_access(0x42));

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_rdmsr_access(0x42);
    vmcs->trap_on_rdmsr_access(0xC0000042UL);

    CHECK(vmcs->m_msr_bitmap_view[8] == 0x4);
    CHECK(vmcs->m_msr_bitmap_view[0x408] == 0x4);

    CHECK_THROWS(vmcs->trap_on_rdmsr_access(0x4000));
    CHECK_THROWS(vmcs->trap_on_rdmsr_access(0xC0004000UL));
}

TEST_CASE("eapis_vmcs_msr: trap on all read msr accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_all_rdmsr_accesses());

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_rdmsr_accesses();

    auto all_set_1 = 0xFF;
    for (auto i = 0x0; i < 0x800; i++) {
        all_set_1 &= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_1 == 0xFF);

    auto all_set_0 = 0x0;
    for (auto i = 0x800; i < 0x1000; i++) {
        all_set_0 |= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_0 == 0x0);
}

TEST_CASE("eapis_vmcs_msr: pass through read msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_rdmsr_access(0x42));

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_rdmsr_accesses();

    vmcs->pass_through_rdmsr_access(0x42);
    vmcs->pass_through_rdmsr_access(0xC0000042UL);

    CHECK(vmcs->m_msr_bitmap_view[8] == 0xFB);
    CHECK(vmcs->m_msr_bitmap_view[0x408] == 0xFB);

    CHECK_THROWS(vmcs->pass_through_rdmsr_access(0x4000));
    CHECK_THROWS(vmcs->pass_through_rdmsr_access(0xC0004000UL));
}

TEST_CASE("eapis_vmcs_msr: pass through all read msr accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_all_rdmsr_accesses());

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_rdmsr_accesses();
    vmcs->trap_on_all_wrmsr_accesses();
    vmcs->pass_through_all_rdmsr_accesses();

    auto all_set_0 = 0x0;
    for (auto i = 0x0; i < 0x800; i++) {
        all_set_0 |= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_0 == 0x0);

    auto all_set_1 = 0xFF;
    for (auto i = 0x800; i < 0x1000; i++) {
        all_set_1 &= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_1 == 0xFF);
}

TEST_CASE("eapis_vmcs_msr: whitelist read msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->whitelist_rdmsr_access({0x42, 0xC0000042UL}));

    vmcs->enable_msr_bitmap();
    vmcs->whitelist_rdmsr_access({0x42, 0xC0000042UL});

    CHECK(vmcs->m_msr_bitmap_view[8] == 0xFB);
    CHECK(vmcs->m_msr_bitmap_view[0x408] == 0xFB);
}

TEST_CASE("eapis_vmcs_msr: black list read msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->blacklist_rdmsr_access({0x42, 0xC0000042UL}));

    vmcs->enable_msr_bitmap();
    vmcs->blacklist_rdmsr_access({0x42, 0xC0000042UL});

    CHECK(vmcs->m_msr_bitmap_view[8] == 0x4);
    CHECK(vmcs->m_msr_bitmap_view[0x408] == 0x4);
}

TEST_CASE("eapis_vmcs_msr: trap on write msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_wrmsr_access(0x42));

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_wrmsr_access(0x42);
    vmcs->trap_on_wrmsr_access(0xC0000042UL);

    CHECK(vmcs->m_msr_bitmap_view[0x808] == 0x4);
    CHECK(vmcs->m_msr_bitmap_view[0xC08] == 0x4);

    CHECK_THROWS(vmcs->trap_on_wrmsr_access(0x4000));
    CHECK_THROWS(vmcs->trap_on_wrmsr_access(0xC0004000UL));
}

TEST_CASE("eapis_vmcs_msr: trap on all write msr accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->trap_on_all_wrmsr_accesses());

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_wrmsr_accesses();

    auto all_set_1 = 0xFF;
    for (auto i = 0x800; i < 0x1000; i++) {
        all_set_1 &= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_1 == 0xFF);

    auto all_set_0 = 0x0;
    for (auto i = 0x0; i < 0x800; i++) {
        all_set_0 |= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_0 == 0x0);
}

TEST_CASE("eapis_vmcs_msr: pass through write msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_wrmsr_access(0x42));

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_wrmsr_accesses();

    vmcs->pass_through_wrmsr_access(0x42);
    vmcs->pass_through_wrmsr_access(0xC0000042UL);

    CHECK(vmcs->m_msr_bitmap_view[0x808] == 0xFB);
    CHECK(vmcs->m_msr_bitmap_view[0xC08] == 0xFB);

    CHECK_THROWS(vmcs->pass_through_wrmsr_access(0x4000));
    CHECK_THROWS(vmcs->pass_through_wrmsr_access(0xC0004000UL));
}

TEST_CASE("eapis_vmcs_msr: pass through all write msr accesses")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->pass_through_all_wrmsr_accesses());

    vmcs->enable_msr_bitmap();
    vmcs->trap_on_all_rdmsr_accesses();
    vmcs->trap_on_all_wrmsr_accesses();
    vmcs->pass_through_all_wrmsr_accesses();

    auto all_set_0 = 0x0;
    for (auto i = 0x800; i < 0x1000; i++) {
        all_set_0 |= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_0 == 0x0);

    auto all_set_1 = 0xFF;
    for (auto i = 0x0; i < 0x800; i++) {
        all_set_1 &= vmcs->m_msr_bitmap_view[i];
    }

    CHECK(all_set_1 == 0xFF);
}

TEST_CASE("eapis_vmcs_msr: whitelist write msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->whitelist_wrmsr_access({0x42, 0xC0000042UL}));

    vmcs->enable_msr_bitmap();
    vmcs->whitelist_wrmsr_access({0x42, 0xC0000042UL});

    CHECK(vmcs->m_msr_bitmap_view[0x808] == 0xFB);
    CHECK(vmcs->m_msr_bitmap_view[0xC08] == 0xFB);
}

TEST_CASE("eapis_vmcs_msr: blacklist write msr access")
{
    MockRepository mocks;
    setup_mm(mocks);
    auto vmcs = setup_vmcs(mocks);

    CHECK_THROWS(vmcs->blacklist_wrmsr_access({0x42, 0xC0000042UL}));

    vmcs->enable_msr_bitmap();
    vmcs->blacklist_wrmsr_access({0x42, 0xC0000042UL});

    CHECK(vmcs->m_msr_bitmap_view[0x808] == 0x4);
    CHECK(vmcs->m_msr_bitmap_view[0xC08] == 0x4);
}

#endif
