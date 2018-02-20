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

#include <bfgsl.h>

#include <list>
#include <unordered_map>

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

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE crs
{
public:

    using mask_t = ::intel_x64::vmcs::value_type;
    using shadow_t = ::intel_x64::vmcs::value_type;

    struct info_t {
        uint64_t val;     // In / Out
        uint64_t shadow;  // Out
    };

    using wrcr0_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using rdcr3_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using wrcr3_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using wrcr4_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using rdcr8_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using wrcr8_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    crs(
        gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~crs();

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
    void enable_wrcr0_trapping(mask_t mask, shadow_t shadow);

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
    void enable_wrcr4_trapping(mask_t mask, shadow_t shadow);

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

#ifndef NDEBUG
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
    void enable_log();

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
    void disable_log();

    /// Dump CR0 Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log();
#endif

public:

    /// @cond

    bool handle_crs(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_cr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_cr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

    bool handle_wrcr0(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_rdcr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_wrcr3(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_wrcr4(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_rdcr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_wrcr8(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

    /// @endcond

private:

    uintptr_t emulate_rdgpr(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs
    );

    void emulate_wrgpr(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs, uintptr_t val
    );

private:

    bfvmm::intel_x64::exit_handler *m_exit_handler;

    std::list<wrcr0_handler_delegate_t> m_wrcr0_handlers;
    std::list<rdcr3_handler_delegate_t> m_rdcr3_handlers;
    std::list<wrcr3_handler_delegate_t> m_wrcr3_handlers;
    std::list<wrcr4_handler_delegate_t> m_wrcr4_handlers;
    std::list<rdcr8_handler_delegate_t> m_rdcr8_handlers;
    std::list<wrcr8_handler_delegate_t> m_wrcr8_handlers;

#ifndef NDEBUG
    bool m_log_enabled{false};
    std::list<::intel_x64::cr0::value_type> m_wrcr0_log;
    std::list<::intel_x64::cr3::value_type> m_rdcr3_log;
    std::list<::intel_x64::cr3::value_type> m_wrcr3_log;
    std::list<::intel_x64::cr4::value_type> m_wrcr4_log;
    std::list<::intel_x64::cr8::value_type> m_rdcr8_log;
    std::list<::intel_x64::cr8::value_type> m_wrcr8_log;
#endif

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

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
