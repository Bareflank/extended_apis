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

#ifndef MSRS_INTEL_X64_EAPIS_H
#define MSRS_INTEL_X64_EAPIS_H

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

class EXPORT_EAPIS_HVE msrs
{
public:

    using msr_t = ::intel_x64::vmcs::value_type;

    struct info_t {
        ::x64::msrs::field_type msr;    // In
        ::x64::msrs::value_type val;    // In / Out
        bool ignore_write;              // Out
        bool ignore_advance;            // Out
    };

    using rdmsr_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    using wrmsr_handler_delegate_t =
        delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    msrs(
        gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~msrs();

public:

    /// Add RDMSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdmsr_handler(msr_t msr, rdmsr_handler_delegate_t &&d);

    /// Trap On RDMSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_msr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_rdmsr_access(msr_t msr);

    /// Trap On All RDMSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to read from any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_rdmsr_accesses();

    /// Pass Through RDMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_rdmsr_access(msr_t msr);

    /// Pass Through All RDMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_rdmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_rdmsr_accesses();

public:

    /// Add WRMSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address to listen to
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrmsr_handler(msr_t msr, wrmsr_handler_delegate_t &&d);

    /// Trap On WRMSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_msr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    void trap_on_wrmsr_access(msr_t msr);

    /// Trap On All WRMSR Accesses
    ///
    /// Sets a '1' in the MSR bitmap corresponding with all of the msrs. All
    /// attempts made by the guest to write to any msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_wrmsr_accesses();

    /// Pass Through WRMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_wrmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    void pass_through_wrmsr_access(msr_t msr);

    /// Pass Through All WRMSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
    /// attempts made by the guest to write to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_wrmsr_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_wrmsr_accesses();

#ifndef NDEBUG
public:

    /// Enable  Log
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

    /// Disable  Log
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

    /// Dump  Log
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

    bool handle_rdmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
    bool handle_wrmsr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

    /// @endcond

private:

    bfvmm::intel_x64::exit_handler *m_exit_handler;

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    gsl::span<uint8_t> m_msr_bitmap_view;

    std::unordered_map<msr_t, std::list<rdmsr_handler_delegate_t>> m_rdmsr_handlers;
    std::unordered_map<msr_t, std::list<wrmsr_handler_delegate_t>> m_wrmsr_handlers;

#ifndef NDEBUG
    bool m_log_enabled{false};
    std::unordered_map<msr_t, std::list<uint64_t>> m_rdmsr_log;
    std::unordered_map<msr_t, std::list<uint64_t>> m_wrmsr_log;
#endif

public:

    /// @cond

    msrs(msrs &&) = default;
    msrs &operator=(msrs &&) = default;

    msrs(const msrs &) = delete;
    msrs &operator=(const msrs &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
