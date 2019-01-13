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

#include <arch/intel_x64/cpuid.h>
#include <hve/arch/intel_x64/cpuid.h>

namespace eapis::intel_x64::cpuid
{

uint32_t display_family(uint32_t feat_eax)
{
    namespace version = ::intel_x64::cpuid::feature_information::eax;

    uint32_t family_id = version::family_id::get(feat_eax);
    if (family_id != 0x0F) {
        return family_id;
    }

    return version::extended_family_id::get(feat_eax) + family_id;
}

uint32_t display_model(uint32_t feat_eax)
{
    namespace version = ::intel_x64::cpuid::feature_information::eax;

    const auto family_id = version::family_id::get(feat_eax);
    if (family_id == 0x06 || family_id == 0x0F) {
        const auto model = version::model::get(feat_eax);
        const auto ext_model = version::extended_model_id::get(feat_eax);

        return (ext_model << 4) | model;
    }

    return version::model::get(feat_eax);
}

}
