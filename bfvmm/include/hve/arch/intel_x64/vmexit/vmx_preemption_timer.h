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

#ifndef VMX_PREEMPTION_TIMER_INTEL_X64_EAPIS_H
#define VMX_PREEMPTION_TIMER_INTEL_X64_EAPIS_H

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

/// VMX Preemption Timer
///
/// Provides an interface for registering handlers for VMX-preemption timer
/// exits.
///
class EXPORT_EAPIS_HVE vmx_preemption_timer_handler
{
public:

    using value_t = uint32_t;

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t = delegate<bool(gsl::not_null<vcpu_t *>)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this VMX-preemption timer handler
    /// @param eapis_vcpu_global_state a pointer to the vCPUs global state
    ///
    vmx_preemption_timer_handler(gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmx_preemption_timer_handler() = default;

public:

    /// Add VMX Preemption Timer Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

    /// Enable exiting
    ///
    /// Example:
    /// @code
    /// this->enable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_exiting();

    /// Disable exiting
    ///
    /// Example:
    /// @code
    /// this->disable_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_exiting();

    /// Set timer
    ///
    /// @expects
    /// @ensures
    ///
    void set_timer(value_t val);

    /// Get timer
    ///
    /// @expects
    /// @ensures
    ///
    value_t get_timer() const;

public:

    /// @cond

    bool handle(gsl::not_null<vcpu_t *> vcpu);

    /// @endcond

private:

    vcpu *m_vcpu;
    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    vmx_preemption_timer_handler(vmx_preemption_timer_handler &&) = default;
    vmx_preemption_timer_handler &operator=(vmx_preemption_timer_handler &&) = default;

    vmx_preemption_timer_handler(const vmx_preemption_timer_handler &) = delete;
    vmx_preemption_timer_handler &operator=(const vmx_preemption_timer_handler &) = delete;

    /// @endcond
};

}

#endif
