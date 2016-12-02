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

    void trap_on_io_access(x64::portio::port_addr_type port);
    void trap_on_all_io_accesses();
    void pass_through_io_access(x64::portio::port_addr_type port);
    void pass_through_all_io_accessed();
    void whitelist_io_access(const std::vector<x64::portio::port_addr_type> &ports);
    void blacklist_io_access(const std::vector<x64::portio::port_addr_type> &ports);

protected:

    void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                      gsl::not_null<vmcs_intel_x64_state *> guest_state) override;

private:

    std::unique_ptr<char[]> m_io_bitmapa;
    std::unique_ptr<char[]> m_io_bitmapb;
    gsl::span<char> m_io_bitmapa_view;
    gsl::span<char> m_io_bitmapb_view;
};

#endif
