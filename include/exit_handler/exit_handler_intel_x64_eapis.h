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

#include <vector>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>

#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

#include <intrinsics/portio_x64.h>

class exit_handler_intel_x64_eapis : public exit_handler_intel_x64
{
public:

    typedef void (exit_handler_intel_x64_eapis::*monitor_trap_callback)();

public:

    using count_type = uint64_t;
    using port_type = x64::portio::port_addr_type;
    using port_list_type = std::vector<port_type>;
    using port_log_type = std::map<port_type, count_type>;
    using denial_list_type = std::vector<std::string>;
    using policy_type = std::map<vp::index_type, std::unique_ptr<vmcall_verifier>>;

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
    /// the guest's instruction pointer is advanced.
    ///
    /// Example:
    /// @code
    /// this->advance_and_resume();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void advance_and_resume();

    /// Register Monitor Trap
    ///
    /// Registers a callback function that will be called
    /// after the next instruction is executed by the guest
    /// by setting the monitor trap flag, and storing the
    /// callback to be called on the next VM exit associated
    /// with the monitor trap flag.
    ///
    /// @note: the callback must be a member function of the
    ///     exit_handler (and it's subclasses)
    ///
    /// Example:
    /// @code
    ///
    /// class my_exit_handler : public exit_handler_intel_x64_eapis
    /// {
    /// public:
    ///     void monitor_trap_callback()
    ///     { <do awesome stuff here> }
    /// };
    ///
    /// ehlr->register_monitor_trap(&my_exit_handler::monitor_trap_callback);
    ///
    /// @endcode
    ///
    /// @expects callback == exit handler (or subclass) member function
    /// @ensures
    ///
    /// @param callback the function to be called on a monitor trap VM exit
    ///
    template<class T, typename = typename std::enable_if<std::is_member_function_pointer<T>::value>>
    void register_monitor_trap(T callback)
    {
        intel_x64::vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
        m_monitor_trap_callback = static_cast<monitor_trap_callback>(callback);
    }

    /// Clear Monitor Trap
    ///
    /// Clears the monitor trap flag in the VMCS and registers an unhandled
    /// callback. This is used internally to disabled the monitor trap
    /// prior to calling a registered callback, but it can be used to
    /// cancel an existing registered callback.
    ///
    /// @code
    /// ehlr->clear_monitor_trap();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void clear_monitor_trap();

    /// Log IO Access
    ///
    /// Enables / disables IO access logging.
    ///
    /// @code
    /// ehlr->log_io_access(true);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param enable set to true to enable IO access logging, false otherwise
    ///
    void log_io_access(bool enable);

    /// Clear IO Access Log
    ///
    /// Clears the IO access log. All previously logged IO accesses will be
    /// removed.
    ///
    /// @code
    /// ehlr->clear_io_access_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void clear_io_access_log();

protected:

    void handle_exit(intel_x64::vmcs::value_type reason) override;

private:

    void handle_exit__monitor_trap_flag();
    void handle_exit__io_instruction();

protected:

    void handle_vmcall_registers(vmcall_registers_t &regs) override;
    void handle_vmcall_data_string_json(const json &ijson, json &ojson) override;

private:

    void handle_vmcall_registers__io_instruction(vmcall_registers_t &regs);
    void handle_vmcall_registers__vpid(vmcall_registers_t &regs);

    bool handle_vmcall_json__verifiers(const json &ijson, json &ojson);
    bool handle_vmcall_json__io_instruction(const json &ijson, json &ojson);
    bool handle_vmcall_json__vpid(const json &ijson, json &ojson);

private:

    void handle_vmcall__clear_denials();
    void handle_vmcall__dump_policy(json &ojson);
    void handle_vmcall__dump_denials(json &ojson);

private:

    void handle_vmcall__trap_on_io_access(port_type port);
    void handle_vmcall__trap_on_all_io_accesses();
    void handle_vmcall__pass_through_io_access(port_type port);
    void handle_vmcall__pass_through_all_io_accesses();
    void handle_vmcall__whitelist_io_access(const port_list_type &ports);
    void handle_vmcall__blacklist_io_access(const port_list_type &ports);
    void handle_vmcall__log_io_access(bool enabled);
    void handle_vmcall__clear_io_access_log();
    void handle_vmcall__io_access_log(json &ojson);

private:

    void handle_vmcall__enable_vpid(bool enabled);

private:

    void unhandled_monitor_trap_callback();
    monitor_trap_callback m_monitor_trap_callback;

private:

    void trap_on_io_access_callback();

    bool m_io_access_log_enabled;
    port_log_type m_io_access_log;

private:

    void clear_denials()
    { m_denials.clear(); }

    template <class T>
    T *get_verifier(vp::index_type index)
    { return static_cast<T *>(m_verifiers[index].get()); }

    void init_policy();
    denial_list_type m_denials;
    policy_type m_verifiers;

public:

    // The following are only marked public for unit testing. Do not use
    // these APIs directly as they may change at any time, and their direct
    // use may be unstable. You have been warned.

    vmcs_intel_x64_eapis *m_vmcs_eapis;

    auto eapis_vmcs()
    {
        if (m_vmcs_eapis == nullptr)
            m_vmcs_eapis = dynamic_cast<vmcs_intel_x64_eapis *>(m_vmcs);

        return m_vmcs_eapis;
    }

public:

    friend class eapis_ut;

    exit_handler_intel_x64_eapis(exit_handler_intel_x64_eapis &&) = default;
    exit_handler_intel_x64_eapis &operator=(exit_handler_intel_x64_eapis &&) = default;

    exit_handler_intel_x64_eapis(const exit_handler_intel_x64_eapis &) = delete;
    exit_handler_intel_x64_eapis &operator=(const exit_handler_intel_x64_eapis &) = delete;
};

#endif
