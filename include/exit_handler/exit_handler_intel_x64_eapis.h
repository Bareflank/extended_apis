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

#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_eapis_verifiers.h>

#include <intrinsics/x86/intel_x64.h>

#ifdef SHOW_VMCALLS
#define vmcall_debug bfdebug
#else
#define vmcall_debug if (0) bfdebug
#endif

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_EXIT_HANDLER
#ifdef SHARED_EAPIS_EXIT_HANDLER
#define EXPORT_EAPIS_EXIT_HANDLER EXPORT_SYM
#else
#define EXPORT_EAPIS_EXIT_HANDLER IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_EXIT_HANDLER
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Exit Handler (EAPIS)
///
/// Provides the exit handler needed by the EAPIS. This is intended to be
/// subclassed, and certain functions need to be handled based on how the
/// VMCS is setup.
///
class EXPORT_EAPIS_EXIT_HANDLER exit_handler_intel_x64_eapis : public exit_handler_intel_x64
{
public:

    /// Monitor Trap Callback Type
    ///
    /// Defines the function signature for a monitor callback function.
    ///
    typedef void (exit_handler_intel_x64_eapis::*monitor_trap_callback)();

public:

    using count_type = uint64_t;                                                        ///< Count type used for logging
    using port_type = x64::portio::port_addr_type;                                      ///< Port type
    using port_list_type = std::vector<port_type>;                                      ///< Port list type
    using port_log_type = std::map<port_type, count_type>;                              ///< Port log type
    using denial_list_type = std::vector<std::string>;                                  ///< Denial list type
    using policy_type = std::map<vp::index_type, std::unique_ptr<vmcall_verifier>>;     ///< VMCall policy type
    using msr_type = x64::msrs::field_type;                                             ///< MSR type
    using msr_list_type = std::vector<msr_type>;                                        ///< MSR list type
    using msr_log_type = std::map<msr_type, count_type>;                                ///< MSR log type
    using gpr_index_type = intel_x64::vmcs::value_type;                                 ///< General purpose register index type
    using gpr_value_type = uintptr_t;                                                   ///< General purpose register value type
    using cr0_value_type = intel_x64::cr0::value_type;                                  ///< CR0 value type
    using cr3_value_type = intel_x64::cr3::value_type;                                  ///< CR3 value type
    using cr4_value_type = intel_x64::cr4::value_type;                                  ///< CR4 value type
    using cr8_value_type = intel_x64::cr8::value_type;                                  ///< CR8 value type

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
    template<typename T, typename = std::enable_if<std::is_member_function_pointer<T>::value>>
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

PROTECTED

    /// Handle Exit
    ///
    /// This function is called when a VMExit occurs. If you turn on your
    /// own VMCS exit controls, or you wish to re-implement existing
    /// functionality, you will have to overload this function
    ///
    /// @param reason the exit reason is passed to this function
    ///
    void handle_exit(intel_x64::vmcs::value_type reason) override;

PRIVATE

    /// @cond

    void handle_exit__monitor_trap_flag();
    void handle_exit__io_instruction();
    void handle_exit__rdmsr();
    void handle_exit__wrmsr();
    void handle_exit__ctl_reg_access();

    /// @endcond

PROTECTED

    /// Callback Functions
    ///
    /// These functions are intended to overloaded if you enable any of the
    /// corresponding VMCS APIs. Each function receives the CR0, and provides
    /// a means to alter the result. The default callbacks simply pass
    /// through the input.
    ///

    /// @cond

    virtual cr0_value_type cr0_ld_callback(cr0_value_type val);
    virtual cr3_value_type cr3_ld_callback(cr3_value_type val);
    virtual cr3_value_type cr3_st_callback(cr3_value_type val);
    virtual cr4_value_type cr4_ld_callback(cr4_value_type val);
    virtual cr8_value_type cr8_ld_callback(cr8_value_type val);
    virtual cr8_value_type cr8_st_callback(cr8_value_type val);

    /// @endcond

PROTECTED

    /// Handle VMCall Functions
    ///
    /// These functions will have to be overloaded if you plan to add your
    /// own VMCalls. Note that if you also want to support the existing VMCalls
    /// you can call into the subclass stack as you wish
    ///

    /// @cond

    void handle_vmcall_registers(vmcall_registers_t &regs) override;
    void handle_vmcall_data_string_json(const json &ijson, json &ojson) override;

    /// @endcond

PRIVATE

    /// @cond

    void handle_vmcall_registers__io_instruction(vmcall_registers_t &regs);
    void handle_vmcall_registers__vpid(vmcall_registers_t &regs);
    void handle_vmcall_registers__msr(vmcall_registers_t &regs);
    void handle_vmcall_registers__rdmsr(vmcall_registers_t &regs);
    void handle_vmcall_registers__wrmsr(vmcall_registers_t &regs);

    /// @endcond

PRIVATE

    /// @cond

    void handle_vmcall__clear_denials();
    void handle_vmcall__dump_policy(json &ojson);
    void handle_vmcall__dump_denials(json &ojson);

    /// @endcond

PRIVATE

    /// @cond

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

    /// @endcond

PRIVATE

    /// @cond

    void handle_vmcall__enable_vpid(bool enabled);

    /// @endcond

PRIVATE

    /// @cond

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

    /// @endcond

PRIVATE

    /// @cond

    void unhandled_monitor_trap_callback();
    monitor_trap_callback m_monitor_trap_callback{
        &exit_handler_intel_x64_eapis::unhandled_monitor_trap_callback};

    /// @endcond

PRIVATE

    /// @cond

    void trap_on_io_access_callback();

    /// @endcond

    bool m_io_access_log_enabled{false};            ///< Is IO access logged?
    port_log_type m_io_access_log;                  ///< The IO access log (a list of strings)

PRIVATE

    bool m_rdmsr_access_log_enabled{false};         ///< Is RDMSR access logged?
    bool m_wrmsr_access_log_enabled{false};         ///< Is WRMSR access logged?
    msr_log_type m_rdmsr_access_log;                ///< The RDMSR access log (a list of strings)
    msr_log_type m_wrmsr_access_log;                ///< The WRMSR access log (a list of strings)

PRIVATE

    /// @cond

    gpr_value_type get_gpr(gpr_index_type index);
    void set_gpr(gpr_index_type index, gpr_value_type val);

    /// @endcond

PRIVATE

    /// @cond

    void clear_denials()
    { m_denials.clear(); }

    template <class T>
    T *get_verifier(vp::index_type index)
    { return static_cast<T *>(m_verifiers[index].get()); }

    void init_policy();

    /// @endcond

    denial_list_type m_denials;                     ///< The denial list (list of strings)
    policy_type m_verifiers;                        ///< List of verifiers (hash or map of verifiers)

PRIVATE

    /// @cond

    void json_success(json &ojson);

    void register_json_vmcall__verifiers();
    void register_json_vmcall__io_instruction();
    void register_json_vmcall__vpid();
    void register_json_vmcall__msr();
    void register_json_vmcall__rdmsr();
    void register_json_vmcall__wrmsr();

    /// @endcond

    std::map<std::string, std::function<void(const json &ijson, json &ojson)>> m_json_commands;     ///< List of JSON commands

public:

    // The following are only marked public for unit testing. Do not use
    // these APIs directly as they may change at any time, and their direct
    // use may be unstable. You have been warned.

    /// @cond

    void set_vmcs(gsl::not_null<vmcs_intel_x64 *> vmcs) override
    {
        m_vmcs = vmcs;
        m_vmcs_eapis = dynamic_cast<vmcs_intel_x64_eapis *>(m_vmcs);
    }

    /// @endcond

    vmcs_intel_x64_eapis *m_vmcs_eapis{nullptr};    ///< Pointer to the EAPIS vmcs

public:

    /// @cond

    exit_handler_intel_x64_eapis(exit_handler_intel_x64_eapis &&) = default;
    exit_handler_intel_x64_eapis &operator=(exit_handler_intel_x64_eapis &&) = default;

    exit_handler_intel_x64_eapis(const exit_handler_intel_x64_eapis &) = delete;
    exit_handler_intel_x64_eapis &operator=(const exit_handler_intel_x64_eapis &) = delete;

    /// @endcond
};

#endif
