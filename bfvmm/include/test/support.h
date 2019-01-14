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

#ifndef EAPIS_TEST_SUPPORT_H
#define EAPIS_TEST_SUPPORT_H

#include <bfarch.h>
#include <bfvmm/test/support.h>

#include "hve.h"

void setup_eapis_test_support()
{
#ifdef BF_INTEL_X64
    g_msrs[::intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000;
    g_msrs[::intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000;
    g_msrs[::intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000;
    g_msrs[::intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000;
    g_msrs[::intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000;
#endif
}

#endif
