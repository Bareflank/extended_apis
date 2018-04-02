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

#include <intrinsics.h>

#include <hve/arch/intel_x64/lapic_register.h>
#include <support/arch/intel_x64/test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

namespace eapis
{
namespace intel_x64
{

namespace msrs_n = ::intel_x64::msrs;
namespace apic_n = ::intel_x64::lapic;
namespace regs_n = ::eapis::intel_x64::lapic_register;

std::set<uint64_t> x2apic_write_only = {
    0x3FU
};

TEST_CASE("lapic_register: uninitialized")
{
    for (const auto reg : regs_n::attributes) {
        CHECK(!regs_n::exists_in_xapic(reg));
        CHECK(!regs_n::exists_in_x2apic(reg));
    }
}

TEST_CASE("lapic_register: check x2apic write-only")
{
    regs_n::init_attributes();

    for (auto i = 0U; i < regs_n::attributes.size(); ++i) {
        if (regs_n::offset_to_msr_addr(i) == msrs_n::ia32_x2apic_self_ipi::addr) {
            CHECK(regs_n::exists_in_x2apic(i));
            CHECK(regs_n::writable_in_x2apic(i));
            CHECK(!regs_n::readable_in_x2apic(i));
            CHECK(x2apic_write_only.count(i) == 1U);
        }
    }
}

TEST_CASE("lapic_register: check xapic read-write")
{
    regs_n::init_attributes();

    for (auto i = 0U; i < regs_n::attributes.size(); ++i) {
        switch (i) {
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x0E0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x310U):
                CHECK(regs_n::exists_in_xapic(i));
                CHECK(regs_n::readable_in_xapic(i));
                CHECK(regs_n::writable_in_xapic(i));
                CHECK(!regs_n::exists_in_x2apic(i));
                CHECK(!regs_n::readable_in_x2apic(i));
                CHECK(!regs_n::writable_in_x2apic(i));
                break;

            default:
                break;
        }
    }
}

TEST_CASE("lapic_register: check both write-only")
{
    regs_n::init_attributes();

    for (auto i = 0U; i < regs_n::attributes.size(); ++i) {
        switch (i) {
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x0B0U):
                CHECK(i == regs_n::msr_addr_to_offset(msrs_n::ia32_x2apic_eoi::addr));
                CHECK(regs_n::exists_in_xapic(i));
                CHECK(regs_n::exists_in_x2apic(i));

                CHECK(regs_n::writable_in_xapic(i));
                CHECK(regs_n::writable_in_x2apic(i));

                CHECK(!regs_n::readable_in_xapic(i));
                CHECK(!regs_n::readable_in_x2apic(i));
                break;

            default:
                break;
        }
    }
}

TEST_CASE("lapic_register: check both read-only")
{
    regs_n::init_attributes();

    for (auto i = 0U; i < regs_n::attributes.size(); ++i) {
        switch (i) {
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x020U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x030U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x0A0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x100U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x110U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x120U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x130U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x140U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x150U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x160U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x170U):

            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x180U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x190U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1A0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1B0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1C0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1D0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1E0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x1F0U):

            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x200U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x210U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x220U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x230U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x240U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x250U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x260U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x270U):

            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x390U):
                CHECK(regs_n::exists_in_xapic(i));
                CHECK(regs_n::exists_in_x2apic(i));
                CHECK(!regs_n::writable_in_xapic(i));
                CHECK(!regs_n::writable_in_x2apic(i));
                CHECK(regs_n::readable_in_xapic(i));
                CHECK(regs_n::readable_in_x2apic(i));
                break;

            default:
                break;
        }
    }
}

TEST_CASE("lapic_register: check both read-write")
{
    regs_n::init_attributes();

    for (auto i = 0U; i < regs_n::attributes.size(); ++i) {
        switch (i) {
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x080U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x0F0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x280U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x2F0U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x300U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x320U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x330U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x340U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x350U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x360U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x370U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x380U):
            case regs_n::mem_addr_to_offset(apic_n::xapic_default_base | 0x3E0U):
                CHECK(regs_n::exists_in_xapic(i));
                CHECK(regs_n::exists_in_x2apic(i));
                CHECK(regs_n::writable_in_xapic(i));
                CHECK(regs_n::writable_in_x2apic(i));
                CHECK(regs_n::readable_in_xapic(i));
                CHECK(regs_n::readable_in_x2apic(i));
                break;

            default:
                break;
        }
    }
}

}
}

#endif
