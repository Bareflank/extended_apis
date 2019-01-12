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
