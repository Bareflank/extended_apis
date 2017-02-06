//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_EAPIS_H
#define VMCS_INTEL_X64_EAPIS_H

#include <gsl/gsl>

#include <vector>
#include <memory>

#include <vmcs/vmcs_intel_x64.h>

#include <intrinsics/x64.h>
#include <intrinsics/msrs_x64.h>
#include <intrinsics/portio_x64.h>

/// WARNING:
///
/// All of these APIs operate on the currently loaded VMCS, as well as on
/// private members. If the currently loaded VMCS is not "this" vmcs,
/// corruption is almost certain. We _do not_ check to make sure that this case
/// is not possible because it would cost far too much to check the currently
/// loaded VMCS on every operation. Thus, the user should take great care to
/// ensure that these APIs are used on the currently loaded VMCS. If this is
/// not the case, run vmcs->load() first to ensure the right VMCS is being
/// used.
///

class vmcs_intel_x64_eapis : public vmcs_intel_x64
{
public:

    using integer_pointer = uintptr_t;
    using port_type = x64::portio::port_addr_type;
    using port_list_type = std::vector<port_type>;
    using msr_type = x64::msrs::field_type;
    using msr_list_type = std::vector<msr_type>;
    using preemption_value_type = x64::msrs::value_type;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vmcs_intel_x64_eapis();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcs_intel_x64_eapis() override  = default;

    /// Enable VPID
    ///
    /// Enables VPID. VPIDs cannot be reused. Re-Enabling VPID
    /// will not consume an additional VPID, but creating a new
    /// VMCS will, so reuse VMCS structures if possible.
    ///
    /// Example:
    /// @code
    /// this->enable_vpid();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void enable_vpid();

    /// Disable VPID
    ///
    /// Disables VPID, and sets the VPID in the VMCS to 0.
    ///
    /// Example:
    /// @code
    /// this->disable_vpid();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void disable_vpid();

    /// Enable IO Bitmaps
    ///
    /// Example:
    /// @code
    /// this->enable_io_bitmaps();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void enable_io_bitmaps();

    /// Disable IO Bitmaps
    ///
    /// Example:
    /// @code
    /// this->disable_io_bitmaps();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void disable_io_bitmaps();

    /// Trap On IO Access
    ///
    /// Sets a '1' in the IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to read/write from/to the provided port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// // Trap on PCI configuration space reads / writes
    /// this->trap_on_io_access(0xCF8);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to trap on
    ///
    virtual void trap_on_io_access(port_type port);

    /// Trap On All IO Access
    ///
    /// Sets a '1' in the IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to read/write from/to any port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// // Trap on all port IO access
    /// this->trap_on_all_io_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void trap_on_all_io_accesses();

    /// Pass Through IO Access
    ///
    /// Sets a '0' in the IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to read/write from/to the provided port will
    /// be executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// // Pass through PCI configuration space reads / writes
    /// this->pass_through_io_access(0xCF8);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    virtual void pass_through_io_access(port_type port);

    /// Pass Through All IO Access
    ///
    /// Sets a '0' in the IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to read/write from/to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// // Pass through all port IO access
    /// this->pass_through_all_io_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void pass_through_all_io_accesses();

    /// White List IO Access
    ///
    /// Runs trap_on_all_io_accesses, and then runs pass_through_io_access on
    /// each port provided (i.e. white-listed ports are passed through, all
    /// other ports trap to the hypervisor)
    ///
    /// Example:
    /// @code
    /// // Pass through PCI configuration space reads / write and
    /// // trap on all other port accesses
    /// this->whitelist_io_access({0xCF8});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param ports the ports to whitelist
    ///
    virtual void whitelist_io_access(const port_list_type &ports);

    /// Black List IO Access
    ///
    /// Runs pass_through_all_io_accessed, and then runs trap_on_io_access on
    /// each port provided (i.e. black-listed ports are trapped, all
    /// other ports are passed through)
    ///
    /// Example:
    /// @code
    /// // Trap on PCI configuration space reads / write and
    /// // pass through all other port accesses
    /// this->whitelist_io_access({0xCF8});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param ports the ports to blacklist
    ///
    virtual void blacklist_io_access(const port_list_type &ports);

    /// Enable EPT
    ///
    /// Enables EPT, and sets up the EPT Pointer (EPTP) in the VMCS.
    /// By default, the EPTP is setup with the paging structures to use
    /// write_back memory, and the accessed / dirty bits are disabled.
    /// Once enabling EPT, you can change these values if desired.
    ///
    /// Example:
    /// @code
    /// this->enable_ept();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void enable_ept();

    /// Disable EPT
    ///
    /// Disables EPT, and sets the EPT Pointer (EPTP) in the VMCS to 0.
    ///
    /// Example:
    /// @code
    /// this->disable_ept();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void disable_ept();

    /// Set EPTP
    ///
    /// Sets the EPTP field in the VMCS to point to the provided EPTP. Note
    /// that write back memory is used for the EPTs.
    ///
    /// Example:
    /// @code
    /// this->set_eptp(root_ept->eptp());
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param eptp the eptp value to use. This should come from the
    ///     root_ept_intel_x64->eptp() function.
    ///
    virtual void set_eptp(integer_pointer eptp);

    /// Enable MSR Bitmap
    ///
    /// Example:
    /// @code
    /// this->enable_msr_bitmap();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void enable_msr_bitmap();

    /// Disable MSR Bitmap
    ///
    /// Example:
    /// @code
    /// this->disable_msr_bitmap();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    virtual void disable_msr_bitmap();

    /// Trap On Read MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_rdmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    virtual void trap_on_rdmsr_access(msr_type msr);

    /// Trap On Write MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_wrmsr_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    virtual void trap_on_wrmsr_access(msr_type msr);

    /// Trap On All Read MSR Accesses
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
    virtual void trap_on_all_rdmsr_accesses();

    /// Trap On All Write MSR Accesses
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
    virtual void trap_on_all_wrmsr_accesses();

    /// Pass Through Read MSR Access
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
    virtual void pass_through_rdmsr_access(msr_type msr);

    /// Pass Through Write MSR Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to write to the provided msr will be
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
    virtual void pass_through_wrmsr_access(msr_type msr);

    /// Pass Through All Read MSR Access
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
    virtual void pass_through_all_rdmsr_accesses();

    /// Pass Through All Write MSR Access
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
    virtual void pass_through_all_wrmsr_accesses();

    /// White List Read MST Access
    ///
    /// Runs trap_on_all_rdmsr_accesses, and then runs
    /// pass_through_rdmsr_access on each msr provided
    /// (i.e. white-listed msrs are passed through, all
    /// other msrs trap to the hypervisor)
    ///
    /// Example:
    /// @code
    /// this->whitelist_rdmsr_access({0x42});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msrs the msrs to whitelist
    ///
    virtual void whitelist_rdmsr_access(msr_list_type msrs);

    /// White List Write MST Access
    ///
    /// Runs trap_on_all_wrmsr_accesses, and then runs
    /// pass_through_wrmsr_access on each msr provided
    /// (i.e. white-listed msrs are passed through, all
    /// other msrs trap to the hypervisor)
    ///
    /// Example:
    /// @code
    /// this->whitelist_wrmsr_access({0x42});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msrs the msrs to whitelist
    ///
    virtual void whitelist_wrmsr_access(msr_list_type msrs);

    /// Black List Read MSR Access
    ///
    /// Runs pass_through_all_rdmsr_accesses, and then runs
    /// trap_on_rdmsr_access on each msr provided
    /// (i.e. black-listed msrs are trapped, all
    /// other msrs are passed through)
    ///
    /// Example:
    /// @code
    /// this->blacklist_rdmsr_access({0xCF8});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msrs the msrs to blacklist
    ///
    virtual void blacklist_rdmsr_access(msr_list_type msrs);

    /// Black List Read MSR Access
    ///
    /// Runs pass_through_all_wrmsr_accesses, and then runs
    /// trap_on_wrmsr_access on each msr provided
    /// (i.e. black-listed msrs are trapped, all
    /// other msrs are passed through)
    ///
    /// Example:
    /// @code
    /// this->blacklist_wrmsr_access({0xCF8});
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msrs the msrs to blacklist
    ///
    virtual void blacklist_wrmsr_access(msr_list_type msrs);

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

protected:

    intel_x64::vmcs::value_type m_vpid;

    std::unique_ptr<uint8_t[]> m_io_bitmapa;
    std::unique_ptr<uint8_t[]> m_io_bitmapb;
    gsl::span<uint8_t> m_io_bitmapa_view;
    gsl::span<uint8_t> m_io_bitmapb_view;

    std::unique_ptr<uint8_t[]> m_msr_bitmap;
    gsl::span<uint8_t> m_msr_bitmap_view;

public:

    friend class eapis_ut;

    vmcs_intel_x64_eapis(vmcs_intel_x64_eapis &&) = default;
    vmcs_intel_x64_eapis &operator=(vmcs_intel_x64_eapis &&) = default;

    vmcs_intel_x64_eapis(const vmcs_intel_x64_eapis &) = delete;
    vmcs_intel_x64_eapis &operator=(const vmcs_intel_x64_eapis &) = delete;
};

#endif
