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

#ifndef TIME_INTEL_X64_EAPIS_H
#define TIME_INTEL_X64_EAPIS_H

#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/cpuid.h>
#include "cpuid.h"

namespace eapis::intel_x64::time
{

//
// The following formula for the TSC frequency (in MHz) is derived from the
// description of the Max Non-Turbo Ratio field of the MSR_PLATFORM_INFO msr:
//
//      tsc_freq_MHz = bus_freq_MHz * MSR_PLATFORM_INFO[15:8]
//      tsc_freq_MHz = bus_freq_MHz * platform_info::max_nonturbo_ratio::get()
//
// Note that, most, if not all, systems that (1) aren't Nehalem
// and (2) support invariant TSC (i.e. cpuid.80000007:EDX[8] == 1)
// have a bus_freq_MHz == 100 MHz.
//
// There is an alternative method for deriving TSC frequency based strictly
// on cpuid. If invariant TSC is supported and cpuid.15H:EBX[31:0] != 0, then
// the following equation holds (note the Hz rather than MHz):
//
//      tsc_freq_Hz = (ART frequency) * (TSC / ART ratio)
//      tsc_freq_Hz = (cpuid.15H:ECX) * (cpuid.15H:EBX / cpuid.15H:EAX)
//
// where the ART a.k.a "Always Running Timer" runs at the core crystal clock
// frequency. But ECX may (and in practice does) return 0, in which case the
// formula is nonsense. Clearly we have to get the ART frequency somewhere
// else, but I haven't been able to find it. Section 18.7.3 presents the
// same formula above and mentions using cpuid.15H with the max turbo ratio,
// but that doesn't make sense either.
//
// For now we just use the MSR_PLATFORM_INFO formula
//
inline uint64_t bus_freq_MHz()
{
    const auto eax = ::intel_x64::cpuid::feature_information::eax::get();
    const auto fam = eapis::intel_x64::cpuid::display_family(eax);
    const auto mod = eapis::intel_x64::cpuid::display_model(eax);

    if (fam != 0x06) {
        return 0;
    }

    switch (mod) {
        case 0x4E: // section 2.16
        case 0x55:
        case 0x5E:
        case 0x66:
        case 0x8E:
        case 0x9E:

        case 0x5C: // table 2-12
        case 0x7A:

        case 0x2A: // table 2-19
        case 0x2D:

        case 0x3A: // table 2-24
        case 0x3E: // table 2-25

        case 0x3C: // table 2-28
        case 0x3F:
        case 0x45:
        case 0x46:

        case 0x3D: // section 2.14
        case 0x47:

        case 0x4F: // table 2-35
        case 0x56:

        case 0x57: // table 2-43
        case 0x85:
            return 100;

        case 0x1A: // table 2-14 (rounded down from 133.33)
        case 0x1E:
        case 0x1F:
        case 0x2E:
            return 133;

        default:
            bfalert_nhex(0, "Unknown cpuid display_model", mod);
            return 0;
    }
}

inline uint64_t tsc_freq_MHz(uint64_t bus_freq_MHz)
{ return bus_freq_MHz * ::intel_x64::msrs::platform_info::max_nonturbo_ratio::get(); }

//
// According to section 25.5.1, the VMX preemption timer (pet)
// ticks every time bit X of the TSC changes, where X is the
// value of IA32_VMX_MISC[4:0]. So
//
// pet_freq = tsc_freq >> IA32_VMX_MISC[4:0]
//
inline uint64_t pet_freq_MHz(uint64_t tsc_freq_MHz)
{
    const auto div = ::intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();
    return tsc_freq_MHz >> div;
}

inline uint64_t pet_freq_MHz()
{
    const uint64_t bus = bus_freq_MHz();
    const uint64_t tsc = tsc_freq_MHz(bus);

    return pet_freq_MHz(tsc);
}

inline bool tsc_supported()
{ return ::intel_x64::cpuid::feature_information::edx::tsc::is_enabled(); }

inline bool invariant_tsc_supported()
{ return ::intel_x64::cpuid::invariant_tsc::edx::available::is_enabled(); }

inline uint32_t art_freq_hz()
{ return ::intel_x64::cpuid::time_stamp_count::ecx::get(); }

inline uint32_t tsc_art_numerator()
{ return ::intel_x64::cpuid::time_stamp_count::ebx::get(); }

inline uint32_t tsc_art_denominator()
{ return ::intel_x64::cpuid::time_stamp_count::eax::get(); }

inline uint32_t tsc_art_ratio(uint32_t numerator, uint32_t denominator)
{ return numerator / denominator; }

inline bool tsc_art_ratio_valid(uint32_t numerator)
{ return numerator > 0; }

inline bool art_freq_valid(uint32_t freq)
{ return freq > 0; }

}

#endif
