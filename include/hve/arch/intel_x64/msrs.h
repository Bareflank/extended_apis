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

#ifndef MSRS_INTEL_X64_EAPIS_H
#define MSRS_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE msrs : public base
{
public:

    struct info_t {
        uint64_t msr;           // In
        uint64_t val;           // In / Out
        bool ignore_write;      // Out
        bool ignore_advance;    // Out
    };

    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    msrs(
        gsl::not_null<exit_handler_t *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~msrs() final;

public:

    /// Add RDMSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdmsr_handler(
        vmcs_n::value_type msr, handler_delegate_t &&d);

    /// Trap On RDMSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_msr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_rdmsr_access(vmcs_n::value_type msr);

    /// Trap On All RDMSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to read from any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_rdmsr_accesses();

    /// Pass Through RDMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_rdmsr_access(vmcs_n::value_type msr);

    /// Pass Through All RDMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_accesses();

public:

    /// Add WRMSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrmsr_handler(
        vmcs_n::value_type msr, handler_delegate_t &&d);

    /// Trap On WRMSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_msr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_wrmsr_access(vmcs_n::value_type msr);

    /// Trap On All WRMSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to write to any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_wrmsr_accesses();

    /// Pass Through WRMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_wrmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_wrmsr_access(vmcs_n::value_type msr);

    /// Pass Through All WRMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to write to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_accesses();

public:

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

public:

    /// @cond

    bool handle_rdmsr(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrmsr(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    exit_handler_t *m_exit_handler;

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    gsl::span<uint8_t> m_msr_bitmap_view;

    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_rdmsr_handlers;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_wrmsr_handlers;

private:

    struct msr_record_t {
        uint64_t msr;
        uint64_t val;
        bool out;           // True == out
        bool dir;           // True == read
    };

    std::list<msr_record_t> m_log;

public:

    /// @cond

    msrs(msrs &&) = default;
    msrs &operator=(msrs &&) = default;

    msrs(const msrs &) = delete;
    msrs &operator=(const msrs &) = delete;

    /// @endcond
};

}
}

#endif
