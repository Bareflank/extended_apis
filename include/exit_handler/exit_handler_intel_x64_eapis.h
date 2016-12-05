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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_H

#include <vmcs/vmcs_intel_x64_eapis.h>

#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

#include <intrinsics/portio_x64.h>

class exit_handler_intel_x64_eapis : public exit_handler_intel_x64
{
public:

    typedef void (exit_handler_intel_x64_eapis::*monitor_trap_callback)();

public:

    using count_type = uint64_t;

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    exit_handler_intel_x64_eapis();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exit_handler_intel_x64_eapis() override = default;

    /// Resume
    ///
    /// Resumes the guest associated with this exit handler.
    /// Note that this is the same as running:
    ///
    /// @code
    /// eapis_vmcs()->resume();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void resume();

    /// Advance and Resume
    ///
    /// Same as resume(), but prior to resuming the guest,
    /// the guest's instruction pointer is advanced. If an
    /// instruction is being emulated, this
    ///
    void advance_and_resume();

    void register_monitor_trap(monitor_trap_callback callback);
    void clear_monitor_trap();

    void log_io_access(bool enable);
    void clear_io_access_log();

protected:

    void handle_exit(intel_x64::vmcs::value_type reason) override;

    void handle_exit__monitor_trap_flag();
    void handle_exit__io_instruction();

protected:

    void handle_vmcall_registers(vmcall_registers_t &regs) override;

    void handle_vmcall_registers__io_instruction(vmcall_registers_t &regs);

protected:

    void handle_vmcall_data_string_json(
        vmcall_registers_t &regs, const json &str,
        const bfn::unique_map_ptr_x64<char> &omap) override;

    bool handle_vmcall_json__verifiers(
        vmcall_registers_t &regs, const json &str,
        const bfn::unique_map_ptr_x64<char> &omap);

    bool handle_vmcall_json__io_instruction(
        vmcall_registers_t &regs, const json &str,
        const bfn::unique_map_ptr_x64<char> &omap);

protected:

    void handle_vmcall__dump_policy(
        vmcall_registers_t &regs, const bfn::unique_map_ptr_x64<char> &omap);

    void handle_vmcall__dump_denials(
        vmcall_registers_t &regs, const bfn::unique_map_ptr_x64<char> &omap);

protected:

    void handle_vmcall__trap_on_io_access(
        x64::portio::port_addr_type port);

    void handle_vmcall__trap_on_all_io_accesses();

    void handle_vmcall__pass_through_io_access(
        x64::portio::port_addr_type port);

    void handle_vmcall__pass_through_all_io_accesses();

    void handle_vmcall__whitelist_io_access(
        std::vector<x64::portio::port_addr_type> ports);

    void handle_vmcall__blacklist_io_access(
        std::vector<x64::portio::port_addr_type> ports);

    void handle_vmcall__log_io_access(
        bool enabled);

    void handle_vmcall__clear_io_access_log();

    void handle_vmcall__io_access_log(
        vmcall_registers_t &regs, const bfn::unique_map_ptr_x64<char> &omap);

private:

    void unhandled_monitor_trap_callback();
    monitor_trap_callback m_monitor_trap_callback;

private:

    void trap_on_io_access_callback();

    bool m_io_access_log_enabled;
    x64::portio::port_addr_type m_trapped_port;
    std::map<x64::portio::port_addr_type, count_type> m_io_access_log;

private:

    template <class T>
    T *get_verifier(vp::index_type index)
    { return static_cast<T *>(m_verifiers[index].get()); }

    void init_policy();
    std::vector<std::string> m_denials;
    std::map<vp::index_type, std::unique_ptr<vmcall_verifier>> m_verifiers;

private:

    vmcs_intel_x64_eapis *eapis_vmcs()
    {
        if (m_vmcs_eapis == nullptr)
            m_vmcs_eapis = dynamic_cast<vmcs_intel_x64_eapis *>(m_vmcs);

        return m_vmcs_eapis;
    }

    vmcs_intel_x64_eapis *m_vmcs_eapis;
};

#endif
