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

#ifndef APIC_INTEL_X64_H
#define APIC_INTEL_X64_H

#include <bfgsl.h>
#include <bftypes.h>
#include <bfmemory.h>

#include <vector>
#include <memory>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Virtual APIC
///
/// TODO:
///
class EXPORT_EAPIS_HVE apic_intel_x64
{
public:

    /// Default Constructor
    ///
    apic_intel_x64();

    /// Default Destructor
    ///
    ~apic_intel_x64() = default;

public:

    // The following functions are documented in the Intel Software Development
    // Manual under the x2APIC Address Space section. Note that most sanity
    // checking is done by the MSR logic coming from the guest as we need to
    // be able to read information coming from actual hardware to be placed
    // in the virtual APIC. Reserved fields are however checked to prevent
    // mistakes.

    /// @cond

    uint32_t id() const;
    void set_id(uint32_t val);

    uint32_t version() const;
    void set_version(uint32_t val);

    uint32_t task_priority() const;
    void set_task_priority(uint32_t val);

    uint32_t processor_priority() const;
    void set_processor_priority(uint32_t val);

    uint32_t end_of_interrupt() const;
    void set_end_of_interrupt(uint32_t val);

    uint32_t logical_destination() const;
    void set_logical_destination(uint32_t val);

    uint32_t spurious_interrupt_vector() const;
    void set_spurious_interrupt_vector(uint32_t val);

    uint32_t in_service_031_000() const;
    void set_in_service_031_000(uint32_t val);

    uint32_t in_service_063_032() const;
    void set_in_service_063_032(uint32_t val);

    uint32_t in_service_095_064() const;
    void set_in_service_095_064(uint32_t val);

    uint32_t in_service_127_096() const;
    void set_in_service_127_096(uint32_t val);

    uint32_t in_service_159_128() const;
    void set_in_service_159_128(uint32_t val);

    uint32_t in_service_191_160() const;
    void set_in_service_191_160(uint32_t val);

    uint32_t in_service_223_192() const;
    void set_in_service_223_192(uint32_t val);

    uint32_t in_service_255_224() const;
    void set_in_service_255_224(uint32_t val);

    uint32_t trigger_mode_031_000() const;
    void set_trigger_mode_031_000(uint32_t val);

    uint32_t trigger_mode_063_032() const;
    void set_trigger_mode_063_032(uint32_t val);

    uint32_t trigger_mode_095_064() const;
    void set_trigger_mode_095_064(uint32_t val);

    uint32_t trigger_mode_127_096() const;
    void set_trigger_mode_127_096(uint32_t val);

    uint32_t trigger_mode_159_128() const;
    void set_trigger_mode_159_128(uint32_t val);

    uint32_t trigger_mode_191_160() const;
    void set_trigger_mode_191_160(uint32_t val);

    uint32_t trigger_mode_223_192() const;
    void set_trigger_mode_223_192(uint32_t val);

    uint32_t trigger_mode_255_224() const;
    void set_trigger_mode_255_224(uint32_t val);

    uint32_t interrupt_request_031_000() const;
    void set_interrupt_request_031_000(uint32_t val);

    uint32_t interrupt_request_063_032() const;
    void set_interrupt_request_063_032(uint32_t val);

    uint32_t interrupt_request_095_064() const;
    void set_interrupt_request_095_064(uint32_t val);

    uint32_t interrupt_request_127_096() const;
    void set_interrupt_request_127_096(uint32_t val);

    uint32_t interrupt_request_159_128() const;
    void set_interrupt_request_159_128(uint32_t val);

    uint32_t interrupt_request_191_160() const;
    void set_interrupt_request_191_160(uint32_t val);

    uint32_t interrupt_request_223_192() const;
    void set_interrupt_request_223_192(uint32_t val);

    uint32_t interrupt_request_255_224() const;
    void set_interrupt_request_255_224(uint32_t val);

    uint32_t error_status() const;
    void set_error_status(uint32_t val);

    uint32_t lvt_cmci() const;
    void set_lvt_cmci(uint32_t val);

    uint64_t interrupt_command() const;
    void set_interrupt_command(uint64_t val);

    uint32_t lvt_timer() const;
    void set_lvt_timer(uint32_t val);

    uint32_t lvt_thermal_sensor() const;
    void set_lvt_thermal_sensor(uint32_t val);

    uint32_t lvt_performance_monitoring() const;
    void set_lvt_performance_monitoring(uint32_t val);

    uint32_t lvt_lint0() const;
    void set_lvt_lint0(uint32_t val);

    uint32_t lvt_lint1() const;
    void set_lvt_lint1(uint32_t val);

    uint32_t lvt_error() const;
    void set_lvt_error(uint32_t val);

    uint32_t initial_count() const;
    void set_initial_count(uint32_t val);

    uint32_t current_count() const;
    void set_current_count(uint32_t val);

    uint32_t divide_configuration() const;
    void set_divide_configuration(uint32_t val);

    /// @endcond

private:

    /// The virtual-APIC page
    ///
    /// This page is designed to mimic both the MMIO address map for the
    /// original xAPIC, as well as the layout used by the virtual-APIC page
    /// provided by newer versions of VMX. The default implementation doesn't
    /// use the virtual-APIC page, but this could be used if desired based
    /// on this design.
    ///
    std::unique_ptr<uint32_t[]> m_vapic_page_owner{std::make_unique<uint32_t[]>(1024)};
    gsl::span<uint32_t> m_vapic_page{m_vapic_page_owner.get(), 1024};

public:

    /// @cond

    apic_intel_x64(apic_intel_x64 &&) noexcept = default;
    apic_intel_x64 &operator=(apic_intel_x64 &&) noexcept = default;

    apic_intel_x64(const apic_intel_x64 &) = delete;
    apic_intel_x64 &operator=(const apic_intel_x64 &) = delete;

    /// @endcond

};

#endif
