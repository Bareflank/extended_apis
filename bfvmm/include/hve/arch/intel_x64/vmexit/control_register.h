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

#include <list>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

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

/// Control Register
///
/// Provides an interface for enabling/disabling exiting on control register
/// access. Users may supply handlers and specify shadow values (for CR0 and
/// CR4).
///
class EXPORT_EAPIS_HVE control_register_handler
{
public:

    ///
    /// Info
    ///
    /// This struct is created by control_register_handler::handle before being
    /// passed to each registered handler.
    ///
    struct info_t {

        /// Value (in/out)
        ///
        /// The value the guest VM would like the CR to be, or'd with the
        /// fixed0 bits which the CR must be. This is the value that will be
        /// writen to the CR
        ///
        uint64_t val;

        /// Shadow (out)
        ///
        /// The value the guest VM would like the CR to be. This is the value
        /// that will be written to the shadow
        ///
        ///
        uint64_t shadow;

        /// Ignore write (out)
        ///
        /// If true, do not update the guest's register state. It is assumed
        /// the handler has already done this.
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
    /// @param vcpu the vcpu object for this control register handler
    ///
    control_register_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~control_register_handler() = default;

public:

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr0_handler(const handler_delegate_t &d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr3_handler(const handler_delegate_t &d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr3_handler(const handler_delegate_t &d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr4_handler(const handler_delegate_t &d);

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
    /// @param mask the value of the cr0 guest/host mask to set in the vmcs
    ///
    void enable_wrcr0_exiting(vmcs_n::value_type mask);

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
    /// @param mask the value of the cr4 guest/host mask to set in the vmcs
    ///
    void enable_wrcr4_exiting(vmcs_n::value_type mask);

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    bool handle_cr0(gsl::not_null<vcpu_t *> vcpu);
    bool handle_cr3(gsl::not_null<vcpu_t *> vcpu);
    bool handle_cr4(gsl::not_null<vcpu_t *> vcpu);

    bool handle_wrcr0(gsl::not_null<vcpu_t *> vcpu);
    bool handle_rdcr3(gsl::not_null<vcpu_t *> vcpu);
    bool handle_wrcr3(gsl::not_null<vcpu_t *> vcpu);
    bool handle_wrcr4(gsl::not_null<vcpu_t *> vcpu);

private:

    vcpu *m_vcpu;

    std::list<handler_delegate_t> m_wrcr0_handlers;
    std::list<handler_delegate_t> m_rdcr3_handlers;
    std::list<handler_delegate_t> m_wrcr3_handlers;
    std::list<handler_delegate_t> m_wrcr4_handlers;

public:

    /// @cond

    control_register_handler(control_register_handler &&) = default;
    control_register_handler &operator=(control_register_handler &&) = default;

    control_register_handler(const control_register_handler &) = delete;
    control_register_handler &operator=(const control_register_handler &) = delete;

    /// @endcond
};

}

#endif
