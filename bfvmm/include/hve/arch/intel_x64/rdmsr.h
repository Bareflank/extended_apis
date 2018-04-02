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

#ifndef RDMSR_INTEL_X64_EAPIS_H
#define RDMSR_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class hve;

/// RDMSR
///
/// Provides an interface for registering handlers for rdmsr exits
/// Handlers can be registered a specific MSR address.
///
class EXPORT_EAPIS_HVE rdmsr : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by rdmsr::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// MSR (in)
        ///
        /// The address of the msr the guest tried to read from.
        ///
        /// default: vmcs->save_state()->rcx
        ///
        uint64_t msr;

        /// Value (in/out)
        ///
        /// The value of from the read to update guest state with.
        ///
        /// default: exit_handler::emulate_rdmsr(vmcs->save_state()->rcx)
        ///
        uint64_t val;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state with the default value
        /// of info.val.
        ///
        /// default: false
        ///
        bool ignore_write;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer (i.e. because
        /// your handler (that returns true) already did).
        ///
        bool ignore_advance;
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hve the hve object for this rdmsr handler
    ///
    rdmsr(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~rdmsr() final;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(
        vmcs_n::value_type msr, handler_delegate_t &&d);

    /// Trap On Access
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
    void trap_on_access(vmcs_n::value_type msr);

    /// Trap On All Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the rdmsr. All
    /// attempts made by the guest to read from any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_access(vmcs_n::value_type msr);

    /// Pass Through All Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_accesses();

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

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    gsl::span<uint8_t> m_msr_bitmap;
    gsl::not_null<exit_handler_t *> m_exit_handler;

    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_handlers;

private:

    struct msr_record_t {
        uint64_t msr;
        uint64_t val;
    };

    std::list<msr_record_t> m_log;

public:

    /// @cond

    rdmsr(rdmsr &&) = default;
    rdmsr &operator=(rdmsr &&) = default;

    rdmsr(const rdmsr &) = delete;
    rdmsr &operator=(const rdmsr &) = delete;

    /// @endcond
};

}
}

#endif
