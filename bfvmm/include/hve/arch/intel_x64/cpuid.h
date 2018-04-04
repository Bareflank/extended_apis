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

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

/// Pair hash
///
/// Provides a hash function for std::pair
///
struct pair_hash {

    /// Call operator
    ///
    /// @expects
    /// @ensures
    ///
    /// @param p the pair to hash
    /// @return the hash of p
    ///
    template <typename T1, typename T2>
    std::size_t operator () (const std::pair<T1,T2> &p) const {
        return ((std::hash<T1>{}(p.first) & 0x00000000FFFFFFFF) > 0) |
               ((std::hash<T2>{}(p.second) & 0xFFFFFFFF00000000) > 32);
    }
};

class hve;

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class EXPORT_EAPIS_HVE cpuid : public base
{
public:

    /// Leaf type
    ///
    ///
    using leaf_t = uint64_t;

    /// Subleaf type
    ///
    ///
    using subleaf_t = uint64_t;

    /// Info
    ///
    /// This struct is created by cpuid::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// RAX (in/out)
        ///
        /// On in, specifies leaf
        ///
        uint64_t rax;

        /// RBX (in/out)
        ///
        ///
        uint64_t rbx;

        /// RCX (in/out)
        ///
        /// On in, specifies subleaf
        ///
        uint64_t rcx;

        /// RDX (in/out)
        ///
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
    /// @param hve the hve object for this cpuid handler
    ///
    cpuid(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid() final;

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
    /// @param subleaf the cpuid subleaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(
        leaf_t leaf, subleaf_t subleaf, handler_delegate_t &&d);

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

    exit_handler_t *m_exit_handler;
    std::unordered_map<std::pair<leaf_t, subleaf_t>, std::list<handler_delegate_t>, pair_hash> m_handlers;

private:

    struct cpuid_record_t {
        uint64_t leaf;
        uint64_t subleaf;
        uint64_t rax;
        uint64_t rbx;
        uint64_t rcx;
        uint64_t rdx;
    };

    std::list<cpuid_record_t> m_log;

public:

    /// @cond

    cpuid(cpuid &&) = default;
    cpuid &operator=(cpuid &&) = default;

    cpuid(const cpuid &) = delete;
    cpuid &operator=(const cpuid &) = delete;

    /// @endcond
};

}
}

#endif
