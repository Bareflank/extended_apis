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

struct pair_hash {
    template <typename T1, typename T2>
    std::size_t operator () (const std::pair<T1,T2> &p) const {
        return ((std::hash<T1>{}(p.first) & 0x00000000FFFFFFFF) > 0) |
               ((std::hash<T2>{}(p.second) & 0xFFFFFFFF00000000) > 32);
    }
};

class hve;

class EXPORT_EAPIS_HVE cpuid : public base
{
public:

    using leaf_t = uint64_t;
    using subleaf_t = uint64_t;

    struct info_t {
        uint64_t rax;           // In / Out
        uint64_t rbx;           // In / Out
        uint64_t rcx;           // In / Out
        uint64_t rdx;           // In / Out
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
    /// @expects
    /// @ensures
    ///
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
