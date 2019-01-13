//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>
#include <hve/arch/intel_x64/ept.h>

using namespace eapis::intel_x64;

TEST_CASE("constructor")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);

    CHECK_NOTHROW(ept_handler(eapis, &g_eapis_vcpu_global_state));
}

TEST_CASE("set_eptp")
{
    setup_eapis_test_support();

    MockRepository mocks;
    auto eapis = setup_eapis(mocks);
    auto handler = ept_handler(eapis, &g_eapis_vcpu_global_state);

    auto mm = ept::mmap{};

    handler.set_eptp(&mm);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());

    handler.set_eptp(nullptr);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_disabled());

    handler.set_eptp(&mm);
    handler.set_eptp(&mm);
    handler.set_eptp(&mm);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());

    handler.set_eptp(nullptr);
    CHECK(vmcs_n::secondary_processor_based_vm_execution_controls::enable_ept::is_disabled());
}
