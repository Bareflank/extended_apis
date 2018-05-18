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

#ifndef BASE_INTEL_X64_EAPIS_H
#define BASE_INTEL_X64_EAPIS_H

#include <bfgsl.h>

#include <list>
#include <unordered_map>

#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>

#ifndef EAPIS_LOG_MAX
#define EAPIS_LOG_MAX 10
#endif

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Namespaces
// -----------------------------------------------------------------------------

namespace vmcs_n = ::intel_x64::vmcs;

// -----------------------------------------------------------------------------
// Aliases
// -----------------------------------------------------------------------------

using vmcs_t = bfvmm::intel_x64::vmcs;
using exit_handler_t = bfvmm::intel_x64::exit_handler;

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

/// Base
///
/// Provides an interface for shared features of handlers for the various
/// exit reasons. New exit reasons may be handled by extending this class
/// with the relevant exit-reason-specific code.
///
class EXPORT_EAPIS_HVE base
{

public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    base() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    virtual ~base() = default;

public:

    /// Enable Log
    ///
    /// Example:
    /// @code
    /// this->enable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_log()
    { m_log_enabled = true; }

    /// Disable Log
    ///
    /// Example:
    /// @code
    /// this->disable_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void disable_log()
    { m_log_enabled = true; }

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
    virtual void dump_log() = 0;

    /// Add Record to Log
    ///
    /// Example:
    /// @code
    /// this->add_record();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param log The log to add a record to
    /// @param record The record to add to the log
    ///
    template<typename T> void
    add_record(std::list<T> &log, const T &record)
    {
        if (log.size() < EAPIS_LOG_MAX) {
            log.push_back(record);
        }
    }

protected:

    /// Emulate read of general-purpose register
    ///
    /// Reads from the register specified by the general_purpose_register
    /// field of the exit qualification (i.e. the register the guest read
    /// from).
    ///
    /// @note the qualification used below is control_register_access. It
    ///       is used for _every_ exit qualification that has a
    ///       general_purpose_register (gpr) field. This is OK because the
    ///       encoding is the same for each exit_qualification with a gpr
    ///       subfield.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs The vmcs containing the guest register state
    /// @return the value written by the guest to the given gpr
    ///
    uintptr_t emulate_rdgpr(gsl::not_null<vmcs_t *> vmcs)
    {
        using namespace vmcs_n::exit_qualification::control_register_access;

        switch (general_purpose_register::get()) {
            case general_purpose_register::rax:
                return vmcs->save_state()->rax;

            case general_purpose_register::rbx:
                return vmcs->save_state()->rbx;

            case general_purpose_register::rcx:
                return vmcs->save_state()->rcx;

            case general_purpose_register::rdx:
                return vmcs->save_state()->rdx;

            case general_purpose_register::rsp:
                return vmcs->save_state()->rsp;

            case general_purpose_register::rbp:
                return vmcs->save_state()->rbp;

            case general_purpose_register::rsi:
                return vmcs->save_state()->rsi;

            case general_purpose_register::rdi:
                return vmcs->save_state()->rdi;

            case general_purpose_register::r8:
                return vmcs->save_state()->r08;

            case general_purpose_register::r9:
                return vmcs->save_state()->r09;

            case general_purpose_register::r10:
                return vmcs->save_state()->r10;

            case general_purpose_register::r11:
                return vmcs->save_state()->r11;

            case general_purpose_register::r12:
                return vmcs->save_state()->r12;

            case general_purpose_register::r13:
                return vmcs->save_state()->r13;

            case general_purpose_register::r14:
                return vmcs->save_state()->r14;

            case general_purpose_register::r15:
                return vmcs->save_state()->r15;

            default:
                throw std::runtime_error("emulate_rdgpr: unknown index");
        }
    }

    /// Emulate write of general-purpose register
    ///
    /// Write the given value into the register specified by the
    /// general_purpose_register field of the exit qualification
    /// (i.e. the register the guest attempted to write to).
    ///
    /// @note the qualification used below is control_register_access. It
    ///       is used for _every_ exit qualification that has a
    ///       general_purpose_register (gpr) field. This is OK because the
    ///       encoding is the same for each exit_qualification with a gpr
    ///       subfield.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs containing the guest register state
    /// @param val the to write to the guest register
    ///
    void emulate_wrgpr(gsl::not_null<vmcs_t *> vmcs, uintptr_t val)
    {
        using namespace vmcs_n::exit_qualification::control_register_access;

        switch (general_purpose_register::get()) {
            case general_purpose_register::rax:
                vmcs->save_state()->rax = val;
                return;

            case general_purpose_register::rbx:
                vmcs->save_state()->rbx = val;
                return;

            case general_purpose_register::rcx:
                vmcs->save_state()->rcx = val;
                return;

            case general_purpose_register::rdx:
                vmcs->save_state()->rdx = val;
                return;

            case general_purpose_register::rsp:
                vmcs->save_state()->rsp = val;
                return;

            case general_purpose_register::rbp:
                vmcs->save_state()->rbp = val;
                return;

            case general_purpose_register::rsi:
                vmcs->save_state()->rsi = val;
                return;

            case general_purpose_register::rdi:
                vmcs->save_state()->rdi = val;
                return;

            case general_purpose_register::r8:
                vmcs->save_state()->r08 = val;
                return;

            case general_purpose_register::r9:
                vmcs->save_state()->r09 = val;
                return;

            case general_purpose_register::r10:
                vmcs->save_state()->r10 = val;
                return;

            case general_purpose_register::r11:
                vmcs->save_state()->r11 = val;
                return;

            case general_purpose_register::r12:
                vmcs->save_state()->r12 = val;
                return;

            case general_purpose_register::r13:
                vmcs->save_state()->r13 = val;
                return;

            case general_purpose_register::r14:
                vmcs->save_state()->r14 = val;
                return;

            case general_purpose_register::r15:
                vmcs->save_state()->r15 = val;
                return;

            default:
                throw std::runtime_error("emulate_wrgpr: unknown index");
        }
    }

protected:

    /// Log enabled
    ///
    /// If true, *each* class derived from base will log exit-reason-specific
    /// information on exit (provided also that NDEBUG == 0).
    //
    bool m_log_enabled{false};

public:

    /// @cond

    base(base &&) = default;
    base &operator=(base &&) = default;

    base(const base &) = delete;
    base &operator=(const base &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
