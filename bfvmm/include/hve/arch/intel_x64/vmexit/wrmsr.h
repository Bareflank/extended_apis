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

#ifndef WRMSR_INTEL_X64_EAPIS_H
#define WRMSR_INTEL_X64_EAPIS_H

#include <list>

#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>

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

namespace eapis::intel_x64
{

class vcpu;

/// WRMSR
///
/// Provides an interface for registering handlers for wrmsr exits
/// Handlers can be registered a specific MSR address.
///
class EXPORT_EAPIS_HVE wrmsr_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by wrmsr::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// MSR (in)
        ///
        /// The address of the msr the guest tried to write to.
        ///
        /// default: vmcs->save_state()->rcx
        ///
        uint64_t msr;

        /// Value (in/out)
        ///
        /// The value the guest tried to write
        ///
        /// default: (vmcs->save_state()->rax & 0xFFFFFFFF << 0)  |
        ///          (vmcs->save_state()->rdx & 0xFFFFFFFF << 32) |
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
        delegate<bool(gsl::not_null<vcpu_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu pointer for this wrmsr handler
    ///
    wrmsr_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~wrmsr_handler() = default;

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
        vmcs_n::value_type msr, const handler_delegate_t &d);

    /// Emulate
    ///
    /// Prevents the APIs from talking to physical hardware which means that
    /// no reads or writes are happening with the actual hardware, and
    /// everything must be emulated. This should be used for guests to
    /// prevent guest operations from leaking to the host.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to ignore
    ///
    void emulate(vmcs_n::value_type msr);

    /// Add Default Handler
    ///
    /// This is called when no registered handlers have been called and
    /// the internal implementation is needed. Note that this function
    /// can still return false and let the internal implementation pass
    /// the instruction through
    ///
    /// Also note that the handler registered here is a base exit handler
    /// delegate. The info structure is not passed, and therefor,
    /// no emulation is provided to this handler.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void set_default_handler(const ::handler_delegate_t &d);

public:

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
    /// Sets a '1' in the MSR bitmap corresponding with all of the wrmsr. All
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

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    gsl::span<uint8_t> m_msr_bitmap;

    ::handler_delegate_t m_default_handler;
    std::unordered_map<vmcs_n::value_type, bool> m_emulate;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_handlers;

public:

    /// @cond

    wrmsr_handler(wrmsr_handler &&) = default;
    wrmsr_handler &operator=(wrmsr_handler &&) = default;

    wrmsr_handler(const wrmsr_handler &) = delete;
    wrmsr_handler &operator=(const wrmsr_handler &) = delete;

    /// @endcond
};

}

#endif
