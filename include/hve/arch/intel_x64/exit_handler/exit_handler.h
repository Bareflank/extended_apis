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

#include <deque>
#include <list>
#include <vector>
#include <functional>

#include "../../../../hve/arch/intel_x64/vmcs/vmcs.h"
#include "../../../../hve/arch/intel_x64/exit_handler/exit_handler.h"

#include <intrinsics.h>

#include <bfvmm/memory_manager/object_allocator.h>
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

namespace eapis
{
namespace intel_x64
{

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// Exit Handler (EAPIS)
///
/// Provides the exit handler needed by the EAPIS. This is intended to be
/// subclassed, and certain functions need to be handled based on how the
/// VMCS is setup.
///
class EXPORT_EAPIS_HVE exit_handler : public bfvmm::intel_x64::exit_handler
{
public:

    using count_type = uint64_t;                                                        ///< Count type used for logging
    using port_type = ::x64::portio::port_addr_type;                                    ///< Port type
    using port_list_type = std::vector<port_type>;                                      ///< Port list type
    using denial_list_type = std::vector<std::string>;                                  ///< Denial list type
    using msr_type = ::x64::msrs::field_type;                                           ///< MSR type
    using msr_list_type = std::vector<msr_type>;                                        ///< MSR list type
    using gpr_index_type = ::intel_x64::vmcs::value_type;                               ///< General purpose register index type
    using gpr_value_type = uintptr_t;                                                   ///< General purpose register value type
    using cr0_value_type = ::intel_x64::cr0::value_type;                                ///< CR0 value type
    using cr3_value_type = ::intel_x64::cr3::value_type;                                ///< CR3 value type
    using cr4_value_type = ::intel_x64::cr4::value_type;                                ///< CR4 value type
    using cr8_value_type = ::intel_x64::cr8::value_type;                                ///< CR8 value type
    using vector_type = ::intel_x64::vmcs::value_type;                                  ///< Event vector type
    using event_type = ::intel_x64::vmcs::value_type;                                   ///< Event type
    using error_code_type = ::intel_x64::vmcs::value_type;                              ///< Event error code type
    using instr_len_type = ::intel_x64::vmcs::value_type;                               ///< Event instruction length type
    using tpr_shadow_type = ::intel_x64::cr8::value_type;                               ///< TPR shadow type
    using cpuid_type = ::x64::cpuid::field_type;                                        ///< CPUID type
    using cpuid_key_type = uint64_t;                                                    ///< CPUID key type
    using cpuid_regs_type = ::x64::cpuid::cpuid_regs;                                   ///< CPUID regs type
    using cpuid_emu_map_type = std::map<cpuid_key_type, cpuid_regs_type>;               ///< CPUID emu map type
    using vmcs_type = eapis::intel_x64::vmcs;                                           ///< VMCS type

    /// Monitor Trap Callback Type
    ///
    /// Defines the function signature for a monitor callback function.
    ///
    using monitor_trap_callback = void(exit_handler::*)();

    /// @struct event
    ///
    /// Event Structure
    ///
    /// Each event that is sent / received by the exit handler is broken down
    /// into this structure.
    ///
    /// @var event::vector
    ///     the vector number for the event
    /// @var event::type
    ///     the event's type (edge or level triggered, etc...)
    /// @var event::len (if applicable)
    ///     the instruction length of the instruction at RIP
    /// @var event::error_code (if applicable)
    ///     the error code received / should be delivered
    ///
    struct event {
        vector_type vector;
        event_type type;
        instr_len_type len;
        error_code_type error_code;
    };

public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    exit_handler();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~exit_handler() override = default;

    /// Inject Event
    ///
    /// Queues an interrupt / exception for injection and sets the interrupt
    /// window exiting flag in the VMCS if needed. Once the guest is ready,
    /// an exit will occur and the interrupt / exception will be injected into
    /// the VM.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector vector number for the interrupt / exception
    /// @param type interrupt / exception type
    /// @param len the amount to advance RIP for a software exception
    /// @param error_code the error code to place on the stack for certain hardware exceptions
    ///
    virtual void inject_event(
        vector_type vector, event_type type, instr_len_type len, error_code_type error_code);

#ifndef ENABLE_BUILD_TEST
protected:
#endif

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
    /// class my_exit_handler : public exit_handler
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
        ::intel_x64::vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag::enable();
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

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    // Transition overloads.
    //
    // These functions are overloaded so that interrupts can be properly
    // disabled. as needed

    /// @cond

    void resume() override;
    void advance_and_resume() override;

    /// @endcond

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    // Exit Handlers
    //
    // These functions handle each exit type. Their function names reflect
    // the exit reason, and some of them are abstractions (like
    // handle_event) that simplify the exit by first decoding the exit
    // information and then providing this information to the implementation
    // so that users can overload without having to perform the decoding
    // work.

    /// @cond

    void handle_exit(::intel_x64::vmcs::value_type reason) override;

    virtual void handle_exit__monitor_trap_flag();
    virtual void handle_exit__io_instruction();
    virtual void handle_exit__rdmsr();
    virtual void handle_exit__wrmsr();
    virtual void handle_exit__ctl_reg_access();
    virtual void handle_exit__external_interrupt();
    virtual void handle_exit__interrupt_window();
    virtual void handle_exit__cpuid();
    //     virtual void handle_exit__rdmsr_apic();
    //     virtual void handle_exit__wrmsr_apic();

    /// @endcond

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    // Callback Functions
    //
    // These functions are intended to overloaded if you enable any of the
    // corresponding VMCS APIs. Each function receives the CR, and provides
    // a means to alter the result. The default callbacks simply pass
    // through the input.
    //

    /// @cond

    virtual cr0_value_type cr0_ld_callback(cr0_value_type val);
    virtual cr3_value_type cr3_ld_callback(cr3_value_type val);
    virtual cr3_value_type cr3_st_callback(cr3_value_type val);
    virtual cr4_value_type cr4_ld_callback(cr4_value_type val);
    virtual cr8_value_type cr8_ld_callback(cr8_value_type val);
    virtual cr8_value_type cr8_st_callback(cr8_value_type val);

    /// @endcond

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    // General Purpose Registers
    //
    // The Exit Qualification field in the VMCS defines the register to index
    // mapping that is used by several of the different exit handlers. This
    // mapping is the same, and the following functions provide the general
    // conversions from index to our state save area for this exit handler.
    //

    /// @cond

    gpr_value_type get_gpr(gpr_index_type index);
    void set_gpr(gpr_index_type index, gpr_value_type val);

    /// @endcond

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    /// @cond

    uint64_t create_key(
        cpuid_key_type leaf, cpuid_key_type subleaf);
    uint64_t parse_emulate_cpuid_string(
        std::string reg_string, cpuid_key_type machine_reg);

    /// @endcond

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    // Event Management
    //
    // The following functions are used by the event management code.
    //

    /// @cond

    tpr_shadow_type m_tpr_shadow{0};

    void enable_vmm_exceptions() noexcept;
    void disable_vmm_exceptions() noexcept;

    void queue_event(
        vector_type vector, event_type type, instr_len_type len, error_code_type error_code);

    std::list<event, object_allocator<event, 1>> m_event_queue;

    /// @endcond

#ifndef ENABLE_BUILD_TEST
private:
#endif

    void unhandled_monitor_trap_callback();
    monitor_trap_callback m_monitor_trap_callback{
        &exit_handler::unhandled_monitor_trap_callback};

#ifndef ENABLE_BUILD_TEST
private:
#endif

    /// @cond

    cpuid_emu_map_type m_cpuid_emu_map;

    /// @endcond

public:

    // Set VMCS
    //
    // The following are only marked public for unit testing. Do not use
    // these APIs directly as they may change at any time, and their direct
    // use may be unstable. You have been warned.
    //

    /// @cond

    void
    set_vmcs(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) override
    {
        m_vmcs = vmcs;
        m_vmcs_eapis = dynamic_cast<vmcs_type *>(m_vmcs);
    }

    /// @endcond

    vmcs_type *m_vmcs_eapis{nullptr};    ///< Pointer to the EAPIS vmcs

public:

    /// @cond

    exit_handler(exit_handler &&) = default;
    exit_handler &operator=(exit_handler &&) = default;

    exit_handler(const exit_handler &) = delete;
    exit_handler &operator=(const exit_handler &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
