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

#ifndef CPUID_INTEL_X64_EAPIS_H
#define CPUID_INTEL_X64_EAPIS_H

#include <unordered_map>

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

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class EXPORT_EAPIS_HVE cpuid_handler
{
public:

    /// Leaf type
    ///
    ///
    using leaf_t = uint64_t;

    /// Info
    ///
    /// This struct is created by cpuid_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// RAX (in/out)
        ///
        uint64_t rax;

        /// RBX (in/out)
        ///
        uint64_t rbx;

        /// RCX (in/out)
        ///
        uint64_t rcx;

        /// RDX (in/out)
        ///
        uint64_t rdx;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state with the four
        /// register values above. Set this to true if you do not want the guest
        /// rax, rbx, rcx, or rdx to be written to after your handler completes.
        ///
        /// default: false
        ///
        bool ignore_write;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
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
    /// @param vcpu the vcpu object for this cpuid_handler
    ///
    cpuid_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid_handler() = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the cpuid leaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(leaf_t leaf, const handler_delegate_t &d);

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
    /// @param leaf the address to emulate
    ///
    void emulate(leaf_t leaf);

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

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;

    ::handler_delegate_t m_default_handler;
    std::unordered_map<leaf_t, bool> m_emulate;
    std::unordered_map<leaf_t, std::list<handler_delegate_t>> m_handlers;

public:

    /// @cond

    cpuid_handler(cpuid_handler &&) = default;
    cpuid_handler &operator=(cpuid_handler &&) = default;

    cpuid_handler(const cpuid_handler &) = delete;
    cpuid_handler &operator=(const cpuid_handler &) = delete;

    /// @endcond
};

}

#endif
