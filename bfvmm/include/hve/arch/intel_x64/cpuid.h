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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#ifndef HVE_CPUID_INTEL_X64_H
#define HVE_CPUID_INTEL_X64_H

namespace eapis::intel_x64::cpuid
{

/// display_family
///
/// @param feat_eax the value returned from cpuid at leaf
///        feature_information.
/// @return the value of the display family
uint32_t display_family(uint32_t feat_eax);

/// display_model
///
/// @param feat_eax the value returned from cpuid at leaf
///        feature_information.
/// @return the value of the display model
uint32_t display_model(uint32_t feat_eax);

}

#endif
