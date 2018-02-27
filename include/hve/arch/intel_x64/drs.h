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

#ifndef DRS_INTEL_X64_EAPIS_H
#define DRS_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE drs : public base
{
public:

    struct info_t {
        uint64_t val;           // In / Out
        bool ignore_write;      // Out
        bool ignore_advance;    // Out
    };

    using wrdr7_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    drs(gsl::not_null<exit_handler_t *> exit_handler);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~drs() final;

public:

    /// Add Write DR7 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrdr7_handler(wrdr7_handler_delegate_t &&d);

    /// Enable Write DR7 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_wrdr7_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrdr7_trapping();

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

    bool handle_drs(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    exit_handler_t *m_exit_handler;
    std::list<wrdr7_handler_delegate_t> m_wrdr7_handlers;

private:

    struct dr_record_t {
        uint64_t val;
        bool out;           // True == out
    };

    std::list<dr_record_t> m_log;

public:

    /// @cond

    drs(drs &&) = default;
    drs &operator=(drs &&) = default;

    drs(const drs &) = delete;
    drs &operator=(const drs &) = delete;

    /// @endcond
};

}
}

#endif
