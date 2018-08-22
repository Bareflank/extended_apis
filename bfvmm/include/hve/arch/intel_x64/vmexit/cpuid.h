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

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class vcpu;

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class EXPORT_EAPIS_HVE cpuid_handler : public base
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
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this cpuid_handler
    ///
    cpuid_handler(gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid_handler() final;

public:

    /// Add CPUID Handler
    ///
    /// @note the handler is called only for the (leaf, subleaf)
    ///       pairs passed into this function. If you need to handle
    ///       accesses to leaf not at subleaf, you will need to make
    ///       additional calls with the appropriate subleaves
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the cpuid leaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(leaf_t leaf, const handler_delegate_t &d);

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

    std::unordered_map<leaf_t, std::list<handler_delegate_t>> m_handlers;

private:

    struct record_t {
        uint64_t rax_in;
        uint64_t rbx_in;
        uint64_t rcx_in;
        uint64_t rdx_in;
        uint64_t rax_out;
        uint64_t rbx_out;
        uint64_t rcx_out;
        uint64_t rdx_out;
    };

    std::list<record_t> m_log;

public:

    /// @cond

    cpuid_handler(cpuid_handler &&) = default;
    cpuid_handler &operator=(cpuid_handler &&) = default;

    cpuid_handler(const cpuid_handler &) = delete;
    cpuid_handler &operator=(const cpuid_handler &) = delete;

    /// @endcond
};

}
}

#endif
