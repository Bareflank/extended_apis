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

#ifndef VMCS_INTEL_X64_EAPIS
#define VMCS_INTEL_X64_EAPIS

#include <gsl/gsl>

#include <vector>
#include <memory>

#include <vmcs/vmcs_intel_x64.h>

#include <intrinsics/x64.h>
#include <intrinsics/portio_x64.h>

class vmcs_intel_x64_eapis : public vmcs_intel_x64
{
public:

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

    void enable_vpid();
    void disable_vpid();

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
    void trap_on_io_access(x64::portio::port_addr_type port);

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
    void trap_on_all_io_accesses();

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
    /// @param the port to pass through
    ///
    void pass_through_io_access(x64::portio::port_addr_type port);

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
    void pass_through_all_io_accesses();

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
    void whitelist_io_access(const std::vector<x64::portio::port_addr_type> &ports);

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
    void blacklist_io_access(const std::vector<x64::portio::port_addr_type> &ports);

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

private:

    intel_x64::vmcs::value_type m_vpid;

    std::unique_ptr<char[]> m_io_bitmapa;
    std::unique_ptr<char[]> m_io_bitmapb;
    gsl::span<char> m_io_bitmapa_view;
    gsl::span<char> m_io_bitmapb_view;
};

#endif
