//
// Bareflank Hypervisor Examples
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

#include <mutex>
#include <vector>
#include <memory>

#include <vmcs/vmcs_intel_x64.h>

#include <vmcs/ept_intel_x64.h>
#include <vmcs/ept_attr_intel_x64.h>

#include <intrinsics/x64.h>
#include <intrinsics/msrs_x64.h>
#include <intrinsics/portio_x64.h>

class vmcs_intel_x64_eapis : public vmcs_intel_x64
{
public:

    using port_type = x64::portio::port_addr_type;
    using port_list_type = std::vector<port_type>;
    using msr_type = x64::msrs::field_type;
    using msr_list_type = std::vector<msr_type>;
    using integer_pointer = uintptr_t;
    using attr_type = intel_x64::ept::memory_attr::attr_type;
    using size_type = size_t;

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

    /// Trap On IO Access
    ///
    /// Sets a '1' in IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to write to the provided port will
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
    /// Sets a '1' in IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to write to any port will
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
    /// Sets a '0' in IO bitmaps corresponding with the provided port. All
    /// attempts made by the guest to write to the provided port will be
    /// executed by the guest and will not trap to the hypervisor.
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
    /// Sets a '0' in IO bitmaps corresponding with all of the ports. All
    /// attempts made by the guest to write to any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// // Pass through all port IO access
    /// this->pass_through_all_io_accessed();
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
    /// @expects
    /// @ensures
    ///
    void enable_ept();

    /// Disable EPT
    ///
    /// Disables EPT, and sets the EPT Pointer (EPTP) in the VMCS to 0.
    ///
    /// @expects
    /// @ensures
    ///
    void disable_ept();

    /// Map (1 Gigabytes)
    ///
    /// Maps 1 gigabyte of memory in the extended page tables given a guest
    /// physical address, the actual physical address and a set of attributes.
    ///
    /// @note: the user should ensure that this level of page granularity is
    ///     supported by hardware using intel_x64::msrs::ia32_vmx_ept_vpid_cap
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys_addr the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_1g(integer_pointer gpa, integer_pointer phys_addr, attr_type attr)
    { this->map(gpa, phys_addr, attr, intel_x64::ept::pdpt::size_bytes); }

    /// Map (2 Megabytes)
    ///
    /// Maps 2 megabytes of memory in the extended page tables given a guest
    /// physical address, the actual physical address and a set of attributes.
    ///
    /// @note: the user should ensure that this level of page granularity is
    ///     supported by hardware using intel_x64::msrs::ia32_vmx_ept_vpid_cap
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys_addr the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_2m(integer_pointer gpa, integer_pointer phys_addr, attr_type attr)
    { this->map(gpa, phys_addr, attr, intel_x64::ept::pd::size_bytes); }

    /// Map (1 Kilobytes)
    ///
    /// Maps 4 kilobytes of memory in the extended page tables given a guest
    /// physical address, the actual physical address and a set of attributes.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to map
    /// @param phys_addr the physical address to map the gpa to
    /// @param attr describes how to map the gpa
    ///
    void map_4k(integer_pointer gpa, integer_pointer phys_addr, attr_type attr)
    { this->map(gpa, phys_addr, attr, intel_x64::ept::pt::size_bytes); }

    /// Unmap
    ///
    /// Unmaps memory in the extended page tables give a guest
    /// physical address.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to unmap
    ///
    void unmap(integer_pointer gpa) noexcept;

    /// Setup EPT Identify Map (1g Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 1 gigabyte
    /// of memory granularity. Lower granularity takes up far less memory,
    /// but could result in poor performance if too many EPT Violations are
    /// occurring as a result. In addition, not all granularities are supported
    /// by hardware, and thus the user should detect hardware support prior
    /// to using this function. Higher granularity consumes more memory but
    /// could result in better performance in certain situations, and is likely
    /// better supported on hardware. Users should consider:
    /// - How much memory is available for EPT entries
    /// - Virt -> Guest Phys -> Phys translation time (the deeper the pages go,
    ///   the longer it takes to translate an address)
    /// - Hardware support
    /// - EPT Violation frequency (trapping on a specific address will generate
    ///   more unnecessary VM exits on lower granularities)
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_ept_identity_map_1g(integer_pointer saddr, integer_pointer eaddr);

    /// Setup EPT Identify Map (2m Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 2 megabytes
    /// of memory granularity. Lower granularity takes up far less memory,
    /// but could result in poor performance if too many EPT Violations are
    /// occurring as a result. In addition, not all granularities are supported
    /// by hardware, and thus the user should detect hardware support prior
    /// to using this function. Higher granularity consumes more memory but
    /// could result in better performance in certain situations, and is likely
    /// better supported on hardware. Users should consider:
    /// - How much memory is available for EPT entries
    /// - Virt -> Guest Phys -> Phys translation time (the deeper the pages go,
    ///   the longer it takes to translate an address)
    /// - Hardware support
    /// - EPT Violation frequency (trapping on a specific address will generate
    ///   more unnecessary VM exits on lower granularities)
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_ept_identity_map_2m(integer_pointer saddr, integer_pointer eaddr);

    /// Setup EPT Identify Map (4k Granularity)
    ///
    /// Sets up an identify map in the extended page tables using 4 kilobyte
    /// of memory granularity. Lower granularity takes up far less memory,
    /// but could result in poor performance if too many EPT Violations are
    /// occurring as a result. In addition, not all granularities are supported
    /// by hardware, and thus the user should detect hardware support prior
    /// to using this function. Higher granularity consumes more memory but
    /// could result in better performance in certain situations, and is likely
    /// better supported on hardware. Users should consider:
    /// - How much memory is available for EPT entries
    /// - Virt -> Guest Phys -> Phys translation time (the deeper the pages go,
    ///   the longer it takes to translate an address)
    /// - Hardware support
    /// - EPT Violation frequency (trapping on a specific address will generate
    ///   more unnecessary VM exits on lower granularities)
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void setup_ept_identity_map_4k(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap EPT Identify Map (1g Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_ept_identity_map_1g function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_ept_identity_map_1g(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap EPT Identify Map (2m Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_ept_identity_map_2m function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_ept_identity_map_2m(integer_pointer saddr, integer_pointer eaddr);

    /// Unmap EPT Identify Map (4k Granularity)
    ///
    /// Unmaps an identity map previously mapped using the
    /// setup_ept_identity_map_4k function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param saddr the starting address for the identify map
    /// @param eaddr the ending address for the identify map
    ///
    void unmap_ept_identity_map_4k(integer_pointer saddr, integer_pointer eaddr);

    /// Guest Physical Address To Extended Page Table Entry
    ///
    /// Locates the extended page table entry given a guest physical
    /// address. The entry is guaranteed not to be null (or an exception is
    /// thrown). This function can be used to access an EPTE, enabling the
    /// user to modify any part of the EPTE as desired. It should be noted
    /// that the extended page table owns the EPTE. Unmapping an EPTE
    /// invalidates the EPTE returned by this function.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to lookup
    /// @return the resulting EPTE
    ///
    ept_entry_intel_x64 gpa_to_epte(integer_pointer gpa);

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

    virtual std::mutex &eptp_mutex() const;
    virtual gsl::not_null<integer_pointer *> eptp_entry() const;
    virtual gsl::not_null<ept_intel_x64 *> eptp() const;

    ept_entry_intel_x64 add_page(integer_pointer gpa, size_type size);
    void map(integer_pointer gpa, integer_pointer phys_addr, attr_type attr, size_type size);

protected:

    friend class eapis_ut;

    intel_x64::vmcs::value_type m_vpid;

    std::unique_ptr<uint8_t[]> m_io_bitmapa;
    std::unique_ptr<uint8_t[]> m_io_bitmapb;
    gsl::span<uint8_t> m_io_bitmapa_view;
    gsl::span<uint8_t> m_io_bitmapb_view;
};

#endif
