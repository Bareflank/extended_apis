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

#ifndef CRS_INTEL_X64_EAPIS_H
#define CRS_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE crs : public base
{
public:

    struct info_t {
        uint64_t val;           // In / Out
        uint64_t shadow;        // Out
        bool ignore_write;      // Out
        bool ignore_advance;    // Out
    };

    using wrcr0_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    using rdcr3_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    using wrcr3_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    using wrcr4_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    using rdcr8_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    using wrcr8_handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    crs(
        gsl::not_null<exit_handler_t *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~crs() final;

public:

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr0_handler(wrcr0_handler_delegate_t &&d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr3_handler(rdcr3_handler_delegate_t &&d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr3_handler(wrcr3_handler_delegate_t &&d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr4_handler(wrcr4_handler_delegate_t &&d);

    /// Add Read CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr8_handler(rdcr8_handler_delegate_t &&d);

    /// Add Write CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr8_handler(wrcr8_handler_delegate_t &&d);

    /// Enable Write CR0 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr0_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr0_trapping(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Read CR3 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr3_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr3_trapping();

    /// Enable Write CR3 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr3_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr3_trapping();

    /// Enable Write CR4 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr4_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr4_trapping(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Read CR8 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr8_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr8_trapping();

    /// Enable Write CR8 Trapping
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr8_trapping();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr8_trapping();

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

    bool handle_crs(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    bool handle_cr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_cr8(gsl::not_null<vmcs_t *> vmcs);

    bool handle_wrcr0(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdcr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr4(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdcr8(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr8(gsl::not_null<vmcs_t *> vmcs);

    exit_handler_t *m_exit_handler;

    std::list<wrcr0_handler_delegate_t> m_wrcr0_handlers;
    std::list<rdcr3_handler_delegate_t> m_rdcr3_handlers;
    std::list<wrcr3_handler_delegate_t> m_wrcr3_handlers;
    std::list<wrcr4_handler_delegate_t> m_wrcr4_handlers;
    std::list<rdcr8_handler_delegate_t> m_rdcr8_handlers;
    std::list<wrcr8_handler_delegate_t> m_wrcr8_handlers;

private:

    struct cr_record_t {
        uint64_t val;
        uint64_t shadow;
        bool out;           // True == out
        bool dir;           // True == read
    };

    std::list<cr_record_t> m_cr0_log;
    std::list<cr_record_t> m_cr3_log;
    std::list<cr_record_t> m_cr4_log;
    std::list<cr_record_t> m_cr8_log;

public:

    /// @cond

    crs(crs &&) = default;
    crs &operator=(crs &&) = default;

    crs(const crs &) = delete;
    crs &operator=(const crs &) = delete;

    /// @endcond
};

}
}

#endif
