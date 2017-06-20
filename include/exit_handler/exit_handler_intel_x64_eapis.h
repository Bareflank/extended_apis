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

#ifndef EXIT_HANDLER_INTEL_X64_EAPIS_H
#define EXIT_HANDLER_INTEL_X64_EAPIS_H

#include <vector>
#include <functional>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>

#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

#include <debug.h>
#include <intrinsics/portio_x64.h>

#ifdef SHOW_VMCALLS
#define vmcall_debug bfdebug
#else
#define vmcall_debug if (0) bfdebug
#endif

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
    using msr_type = x64::msrs::field_type;
    using msr_list_type = std::vector<msr_type>;
    using msr_log_type = std::map<msr_type, count_type>;
    using gpr_index_type = intel_x64::vmcs::value_type;
    using gpr_value_type = uintptr_t;
    using cr0_value_type = intel_x64::cr0::value_type;
    using cr3_value_type = intel_x64::cr3::value_type;
    using cr4_value_type = intel_x64::cr4::value_type;
    using cr8_value_type = intel_x64::cr8::value_type;

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
    /// this->register_monitor_trap(&my_exit_handler::monitor_trap_callback);
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
    /// Example:
    /// @code
    /// this->clear_monitor_trap();
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
    /// Example:
    /// @code
    /// this->log_io_access(true);
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
    /// Example:
    /// @code
    /// this->clear_io_access_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void clear_io_access_log();

    /// Log Read MSR Access
    ///
    /// Enables / disables read MSR access logging.
    ///
    /// Example:
    /// @code
    /// this->log_rdmsr_access(true);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param enable set to true to enable read MSR access logging,
    ///     false otherwise
    ///
    void log_rdmsr_access(bool enable);

    /// Log Write MSR Access
    ///
    /// Enables / disables write MSR access logging.
    ///
    /// Example:
    /// @code
    /// this->log_wrmsr_access(true);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param enable set to true to enable write MSR access logging,
    ///     false otherwise
    ///
    void log_wrmsr_access(bool enable);

    /// Clear Read MSR Access Log
    ///
    /// Clears the read MSR access log. All previously logged read MSR
    /// accesses will be removed.
    ///
    /// Example:
    /// @code
    /// this->clear_rdmsr_access_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void clear_rdmsr_access_log();

    /// Clear Write MSR Access Log
    ///
    /// Clears the write MSR access log. All previously logged write MSR
    /// accesses will be removed.
    ///
    /// Example:
    /// @code
    /// this->clear_wrmsr_access_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void clear_wrmsr_access_log();

protected:

    void handle_exit(intel_x64::vmcs::value_type reason) override;

private:

    void handle_exit__monitor_trap_flag();
    void handle_exit__io_instruction();
    void handle_exit__rdmsr();
    void handle_exit__wrmsr();
    void handle_exit__ctl_reg_access();

protected:

    virtual cr0_value_type cr0_ld_callback(cr0_value_type val);
    virtual cr3_value_type cr3_ld_callback(cr3_value_type val);
    virtual cr3_value_type cr3_st_callback(cr3_value_type val);
    virtual cr4_value_type cr4_ld_callback(cr4_value_type val);
    virtual cr8_value_type cr8_ld_callback(cr8_value_type val);
    virtual cr8_value_type cr8_st_callback(cr8_value_type val);

protected:

    void handle_vmcall_registers(vmcall_registers_t &regs) override;
    void handle_vmcall_data_string_json(const json &ijson, json &ojson) override;

private:

    void handle_vmcall_registers__io_instruction(vmcall_registers_t &regs);
    void handle_vmcall_registers__vpid(vmcall_registers_t &regs);
    void handle_vmcall_registers__msr(vmcall_registers_t &regs);
    void handle_vmcall_registers__rdmsr(vmcall_registers_t &regs);
    void handle_vmcall_registers__wrmsr(vmcall_registers_t &regs);

private:

    void handle_vmcall__clear_denials();
    void handle_vmcall__dump_policy(json &ojson);
    void handle_vmcall__dump_denials(json &ojson);

private:

    void handle_vmcall__enable_io_bitmaps(bool enabled);
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

    void handle_vmcall__enable_msr_bitmap(bool enabled);

    void handle_vmcall__trap_on_rdmsr_access(msr_type msr);
    void handle_vmcall__trap_on_all_rdmsr_accesses();
    void handle_vmcall__pass_through_rdmsr_access(msr_type msr);
    void handle_vmcall__pass_through_all_rdmsr_accesses();
    void handle_vmcall__whitelist_rdmsr_access(msr_list_type msrs);
    void handle_vmcall__blacklist_rdmsr_access(msr_list_type msrs);
    void handle_vmcall__log_rdmsr_access(bool enabled);
    void handle_vmcall__clear_rdmsr_access_log();
    void handle_vmcall__rdmsr_access_log(json &ojson);

    void handle_vmcall__trap_on_wrmsr_access(msr_type msr);
    void handle_vmcall__trap_on_all_wrmsr_accesses();
    void handle_vmcall__pass_through_wrmsr_access(msr_type msr);
    void handle_vmcall__pass_through_all_wrmsr_accesses();
    void handle_vmcall__whitelist_wrmsr_access(msr_list_type msrs);
    void handle_vmcall__blacklist_wrmsr_access(msr_list_type msrs);
    void handle_vmcall__log_wrmsr_access(bool enabled);
    void handle_vmcall__clear_wrmsr_access_log();
    void handle_vmcall__wrmsr_access_log(json &ojson);

private:

    void unhandled_monitor_trap_callback();
    monitor_trap_callback m_monitor_trap_callback;

private:

    void trap_on_io_access_callback();

    bool m_io_access_log_enabled;
    port_log_type m_io_access_log;

private:

    bool m_rdmsr_access_log_enabled;
    bool m_wrmsr_access_log_enabled;
    msr_log_type m_rdmsr_access_log;
    msr_log_type m_wrmsr_access_log;

protected:

    gpr_value_type get_gpr(gpr_index_type index);
    void set_gpr(gpr_index_type index, gpr_value_type val);

private:

    void clear_denials()
    { m_denials.clear(); }

    template <class T>
    T *get_verifier(vp::index_type index)
    { return static_cast<T *>(m_verifiers[index].get()); }

    void init_policy();
    denial_list_type m_denials;
    policy_type m_verifiers;

private:

    void json_success(json &ojson);

    void register_json_vmcall__verifiers();
    void register_json_vmcall__io_instruction();
    void register_json_vmcall__vpid();
    void register_json_vmcall__msr();
    void register_json_vmcall__rdmsr();
    void register_json_vmcall__wrmsr();

    std::map<std::string, std::function<void(const json &ijson, json &ojson)>> m_json_commands;

public:

    // The following are only marked public for unit testing. Do not use
    // these APIs directly as they may change at any time, and their direct
    // use may be unstable. You have been warned.

    void set_vmcs(gsl::not_null<vmcs_intel_x64 *> vmcs) override
    {
        m_vmcs = vmcs;
        m_vmcs_eapis = dynamic_cast<vmcs_intel_x64_eapis *>(m_vmcs);
    }

    vmcs_intel_x64_eapis *m_vmcs_eapis;

public:

    friend class eapis_ut;

    exit_handler_intel_x64_eapis(exit_handler_intel_x64_eapis &&) = default;
    exit_handler_intel_x64_eapis &operator=(exit_handler_intel_x64_eapis &&) = default;

    exit_handler_intel_x64_eapis(const exit_handler_intel_x64_eapis &) = delete;
    exit_handler_intel_x64_eapis &operator=(const exit_handler_intel_x64_eapis &) = delete;
};

#endif
