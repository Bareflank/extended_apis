//
// Bareflank Extended APIs
//
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

#ifndef CR_ACCESS_HDLR_INTEL_X64_EAPIS_H
#define CR_ACCESS_HDLR_INTEL_X64_EAPIS_H

#include <map>

#include <bfgsl.h>
#include <bfvmm/hve/arch/intel_x64/vmcs/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler/exit_handler.h>

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

namespace eapis
{
namespace intel_x64
{

namespace reason = ::intel_x64::vmcs::exit_reason::basic_exit_reason;
namespace cra = ::intel_x64::vmcs::exit_qualification::control_register_access;
namespace gpr = cra::general_purpose_register;

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// cr_access
///
///
class EXPORT_EAPIS_HVE cr_access
{
public:
    using cr_access_t = eapis::intel_x64::cr_access;
    using exit_hdlr_t = bfvmm::intel_x64::exit_handler;
    using vmcs_t = bfvmm::intel_x64::vmcs;
    using hdlr_t = delegate<bool(gsl::not_null<vmcs_t *>)>;
    using key_t = ::intel_x64::vmcs::value_type;

    constexpr static auto s_reason = reason::control_register_accesses;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    cr_access() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cr_access() = default;

    /// Enable
    ///
    /// Register the set handlers with the base vmm. These
    /// handlers may be called via any exit after the next vm entry
    ///
    /// @expects
    /// @ensures
    ///
    void enable(gsl::not_null<exit_hdlr_t *> exit_hdlr);

    /// Set default
    ///
    /// Listen for all control register exits and call the supplied
    /// handler when one occurs.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param hdlr the handler to call when a control regsiter
    ///        access exit occurs
    ///
    void set_default(hdlr_t &&hdlr);

    /// Set single-register handler
    ///
    /// Listen for accesses to the control register indicated by the key
    /// and call the supplied handler if one occurs.
    ///
    /// @note that the handler set here will be called
    ///       instead of the default handler (if a default
    ///       has been set).
    ///
    /// @expects
    /// @ensures
    ///
    /// @param key the control register to listen to
    /// @param hdlr the handler to call when an exit at the key occurs
    ///
    void set(const key_t key, hdlr_t &&hdlr);

    /// Clear default
    ///
    /// Clear the default handler. Note that any handlers installed with
    /// @see set will still be called when an exit occurs at that control
    /// register.
    ///
    /// @expects
    /// @ensures
    ///
    void clear_default();

    /// Clear
    ///
    /// Clear the handler at the given key. The handler
    /// is no longer called when an exit occurs at that key.
    ///
    /// @note If a default handler has been set, then that will be called
    ///       after a call to this function
    ///
    /// @expects
    /// @ensures
    ///
    /// @param key the key that identifies the handler to remove
    ///
    void clear(const key_t key);

    /// Handle
    ///
    /// Invoke the handler listening for control register exits
    ///
    /// @note If one exists, only the handler for the single register
    ///       will be called. If no single-register handler has been
    ///       set, then only the default handler will be called if
    ///       one has been set.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs state passed to the handler
    ///
    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @cond

    cr_access(cr_access &&) = default;
    cr_access &operator=(cr_access &&) = default;

    cr_access(const cr_access &) = delete;
    cr_access &operator=(const cr_access &) = delete;

    /// @endcond

private:
    std::map<const key_t, hdlr_t> m_handlers{};
    hdlr_t m_def_hdlr;
};

} // namespace intel_x64
} // namespace eapis

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
