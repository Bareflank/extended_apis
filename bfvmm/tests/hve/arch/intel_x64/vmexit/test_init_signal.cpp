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

// TIDY_EXCLUSION=-performance-move-const-arg
//
// Reason:
//     Tidy complains that the std::move(d)'s used in the add_handler calls
//     have no effect. Removing std::move however results in a compiler error
//     saying the lvalue (d) can't bind to the rvalue.
//

#include <intrinsics.h>

#include <support/arch/intel_x64/test_support.h>
#include <hve/arch/intel_x64/init_signal.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

bool test_handler(gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    return true;
}

namespace eapis
{
namespace intel_x64
{

TEST_CASE("init_signal::init_signal")
{
    auto hve = setup_hve();
    CHECK_NOTHROW(eapis::intel_x64::init_signal(hve.get()));
}

TEST_CASE("init_signal::add_handler")
{
    auto hve = setup_hve();
    auto init_signal = eapis::intel_x64::init_signal(hve.get());
    auto hdlr = init_signal::handler_delegate_t::create<test_handler>();

    CHECK_NOTHROW(init_signal.add_handler(std::move(hdlr)));
}

TEST_CASE("init_signal::handle")
{
    auto hve = setup_hve();
    auto ehlr = hve->exit_handler();

    namespace reason = vmcs_n::exit_reason::basic_exit_reason;

    auto init_signal = eapis::intel_x64::init_signal(hve.get());
    auto hdlr = init_signal::handler_delegate_t::create<test_handler>();
    init_signal.add_handler(std::move(hdlr));
    g_vmcs_fields[vmcs_n::exit_reason::addr] = reason::init_signal;

    CHECK_NOTHROW(ehlr->handle(ehlr));
}

}
}

#endif
