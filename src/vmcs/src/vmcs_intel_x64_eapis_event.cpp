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

#include <intrinsics/x86/intel_x64.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

void
vmcs_intel_x64_eapis::enable_event_management()
{
    // if (intel_x64::cpuid::feature_information::ecx::x2apic::is_disabled()) {
    //     throw std::runtime_error("x2apic not supported: failed to enable event management");
    // }

    // if (x64::msrs::ia32_apic_base::enable_x2apic::is_disabled()) {
    //     throw std::runtime_error("x2apic not enabled: failed to enable event management");
    // }

    // if (primary_processor_based_vm_execution_controls::use_msr_bitmap::is_disabled()) {
    //     throw std::runtime_error("msr bitmaps not enabled: failed to enable event management");
    // }

    // for (auto msr = intel_x64::msrs::ia32_x2apic_beg; msr < intel_x64::msrs::ia32_x2apic_end; msr++) {
    //     this->trap_on_rdmsr_access(msr);
    // }

    // this->enable_cr8_load_hook();
    // this->enable_cr8_store_hook();

    // bfdebug_nhex(0, "Spurious Interrupt Vector Register", x64::msrs::get(0x80FU));
    // bfdebug_nhex(0, "TMR 818", x64::msrs::get(0x818U));
    // bfdebug_nhex(0, "TMR 819", x64::msrs::get(0x819U));
    // bfdebug_nhex(0, "TMR 81A", x64::msrs::get(0x81AU));
    // bfdebug_nhex(0, "TMR 81B", x64::msrs::get(0x81BU));
    // bfdebug_nhex(0, "TMR 81C", x64::msrs::get(0x81CU));
    // bfdebug_nhex(0, "TMR 81D", x64::msrs::get(0x81DU));
    // bfdebug_nhex(0, "TMR 81E", x64::msrs::get(0x81EU));
    // bfdebug_nhex(0, "TMR 81F", x64::msrs::get(0x81FU));

    // bfdebug_nhex(0, "830", x64::msrs::get(0x830U));
    // bfdebug_nhex(0, "832", x64::msrs::get(0x832U));
    // bfdebug_nhex(0, "833", x64::msrs::get(0x833U));
    // bfdebug_nhex(0, "834", x64::msrs::get(0x834U));
    // bfdebug_nhex(0, "835", x64::msrs::get(0x835U));
    // bfdebug_nhex(0, "836", x64::msrs::get(0x836U));
    // bfdebug_nhex(0, "837", x64::msrs::get(0x837U));
    // bfdebug_nhex(0, "838", x64::msrs::get(0x838U));
    // bfdebug_nhex(0, "839", x64::msrs::get(0x839U));

    pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    vm_exit_controls::acknowledge_interrupt_on_exit::enable();
}

void
vmcs_intel_x64_eapis::disable_event_management()
{
    // if (primary_processor_based_vm_execution_controls::use_msr_bitmap::is_disabled()) {
    //     throw std::runtime_error("msr bitmaps not enabled: failed to disable event management");
    // }

    // for (auto msr = intel_x64::msrs::ia32_x2apic_beg; msr < intel_x64::msrs::ia32_x2apic_end; msr++) {
    //     this->pass_through_rdmsr_access(msr);
    // }

    // this->disable_cr8_load_hook();
    // this->disable_cr8_store_hook();

    vm_exit_controls::acknowledge_interrupt_on_exit::enable();
    pin_based_vm_execution_controls::external_interrupt_exiting::disable();
}
