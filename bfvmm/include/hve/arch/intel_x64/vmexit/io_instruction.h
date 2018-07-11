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

#ifndef IO_INSTRUCTION_INTEL_X64_EAPIS_H
#define IO_INSTRUCTION_INTEL_X64_EAPIS_H

#include "../base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class vcpu;

/// IO instruction
///
/// Provides an interface for handling port I/O exits base on the port number
///
class EXPORT_EAPIS_HVE io_instruction_handler : public base
{
public:

    ///
    /// Info
    ///
    /// This struct is created by io_instruction_handler::handle before being
    /// passed to each registered handler. Note that default values are
    /// given for each field below (these are the values contained in the
    /// info struct that is passed to each handler).
    ///
    struct info_t {

        /// Port number
        ///
        /// The port number accessed by the guest.
        ///
        /// default: (rdx & 0xFFFF) if operand encoding == dx
        /// default: vmcs_n::exit_qualification::io_instruction::port_number if
        ///          operand encoding != dx
        ///
        uint64_t port_number;

        /// Size of access
        ///
        /// The size of the accessed operand.
        ///
        /// default: vmcs_n::exit_qualification::io_instruction::size_of_access
        ///
        uint64_t size_of_access;

        /// Address
        ///
        /// For accesses via string instructions, the guest linear address.
        ///
        /// default: vmcs_n::guest_linear_address
        ///
        uint64_t address;

        /// Value
        ///
        /// The value from the port
        ///
        /// default: inb(info.port_number) if 'in' access
        /// default: the value from guest memory at info.address if 'out' access
        ///
        uint64_t val;

        /// Ignore write (out)
        ///
        /// - For 'in' accesses, do not update the guest's memory at info.address with
        ///   info.val if this field is true. Set this to true if your handler
        ///   returns true and has already updated the guest's memory.
        ///
        /// - For 'out' accesses, do not write info.val to the port info.port_number
        ///   if this field is true. Set this to true if your handler
        ///   returns true and has written to the guest's port
        ///
        /// default: false
        ///
        bool ignore_write;

        /// Ignore advance (out)
        ///
        /// If true, do not advance the guest's instruction pointer.
        /// Set this to true if your handler returns true and has already
        /// advanced the guest's instruction pointer.
        ///
        /// default: false
        ///
        bool ignore_advance;
    };

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this io instruction handler
    ///
    io_instruction_handler(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~io_instruction_handler() final;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to listen to
    /// @param in_d the handler to call when an in exit occurs
    /// @param out_d the handler to call when an out exit occurs
    ///
    void add_handler(
        vmcs_n::value_type port,
        handler_delegate_t &&in_d,
        handler_delegate_t &&out_d
    );

    /// Trap On Access
    ///
    /// Sets a '1' in the IO bitmap corresponding with the provided port. All
    /// attempts made by the guest to read from the provided port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_port_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to trap on
    ///
    void trap_on_access(vmcs_n::value_type port);

    /// Trap On All Accesses
    ///
    /// Sets a '1' in the IO bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will
    /// trap to hypervisor.
    ///
    /// Example:
    /// @code
    /// this->trap_on_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void trap_on_all_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the IO bitmap corresponding with the provided port. All
    /// attempts made by the guest to read from the provided port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_access(0x42);
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    void pass_through_access(vmcs_n::value_type port);

    /// Pass Through All Access
    ///
    /// Sets a '0' in the IO bitmap corresponding with all of the ports. All
    /// attempts made by the guest to read from any port will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// Example:
    /// @code
    /// this->pass_through_all_accesses();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void pass_through_all_accesses();

public:

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final;

public:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    bool handle_in(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    bool handle_out(gsl::not_null<vmcs_t *> vmcs, info_t &info);

    void emulate_in(info_t &info);
    void emulate_out(info_t &info);

    void load_operand(gsl::not_null<vmcs_t *> vmcs, info_t &info);
    void store_operand(gsl::not_null<vmcs_t *> vmcs, info_t &info);

    gsl::span<uint8_t> m_io_bitmaps;
    gsl::not_null<exit_handler_t *> m_exit_handler;

    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_in_handlers;
    std::unordered_map<vmcs_n::value_type, std::list<handler_delegate_t>> m_out_handlers;

private:

    struct port_record_t {
        uint64_t port_number;
        uint64_t size_of_access;
        uint64_t direction_of_access;
        uint64_t address;
        uint64_t val;
    };

    std::list<port_record_t> m_log;

public:

    /// @cond

    io_instruction_handler(io_instruction_handler &&) = default;
    io_instruction_handler &operator=(io_instruction_handler &&) = default;

    io_instruction_handler(const io_instruction_handler &) = delete;
    io_instruction_handler &operator=(const io_instruction_handler &) = delete;

    /// @endcond
};

}
}

#endif
