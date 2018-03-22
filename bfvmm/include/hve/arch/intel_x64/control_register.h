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

#ifndef CONTROL_REGISTER_INTEL_X64_EAPIS_H
#define CONTROL_REGISTER_INTEL_X64_EAPIS_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class hve;

class EXPORT_EAPIS_HVE control_register : public base
{
public:

    struct info_t {
        uint64_t val;           // In / Out
        uint64_t shadow;        // Out
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
    control_register(gsl::not_null<eapis::intel_x64::hve *> hve);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~control_register() final;

public:

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr0_handler(handler_delegate_t &&d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr3_handler(handler_delegate_t &&d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr3_handler(handler_delegate_t &&d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr4_handler(handler_delegate_t &&d);

    /// Add Read CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr8_handler(handler_delegate_t &&d);

    /// Add Write CR8 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr8_handler(handler_delegate_t &&d);

public:

    /// Enable Write CR0 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr0_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr0_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Read CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr3_exiting();

    /// Enable Write CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr3_exiting();

    /// Enable Write CR4 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr4_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr4_exiting(
        vmcs_n::value_type mask, vmcs_n::value_type shadow);

    /// Enable Read CR8 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr8_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr8_exiting();

    /// Enable Write CR8 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr8_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr8_exiting();

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

    bool handle_cr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_cr8(gsl::not_null<vmcs_t *> vmcs);

    bool handle_wrcr0(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdcr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr3(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr4(gsl::not_null<vmcs_t *> vmcs);
    bool handle_rdcr8(gsl::not_null<vmcs_t *> vmcs);
    bool handle_wrcr8(gsl::not_null<vmcs_t *> vmcs);

private:

    gsl::not_null<exit_handler_t *> m_exit_handler;

    std::list<handler_delegate_t> m_wrcr0_handlers;
    std::list<handler_delegate_t> m_rdcr3_handlers;
    std::list<handler_delegate_t> m_wrcr3_handlers;
    std::list<handler_delegate_t> m_wrcr4_handlers;
    std::list<handler_delegate_t> m_rdcr8_handlers;
    std::list<handler_delegate_t> m_wrcr8_handlers;

private:

    struct record_t {
        uint64_t val;
        uint64_t shadow;
    };

    std::list<record_t> m_cr0_log;
    std::list<record_t> m_cr3_log;
    std::list<record_t> m_cr4_log;
    std::list<record_t> m_cr8_log;

public:

    /// @cond

    control_register(control_register &&) = default;
    control_register &operator=(control_register &&) = default;

    control_register(const control_register &) = delete;
    control_register &operator=(const control_register &) = delete;

    /// @endcond
};

}
}

#endif
