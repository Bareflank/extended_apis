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

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis
{
namespace intel_x64
{

class EXPORT_EAPIS_HVE io_instruction : public base
{
public:

    struct info_t {
        uint64_t port_number;           // In
        uint64_t size_of_access;        // In
        uint64_t address;               // In
        uint64_t val;                   // In / Out
        bool ignore_write;              // Out
        bool ignore_advance;            // Out
    };

    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>, info_t &)>;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    io_instruction(
        gsl::span<uint8_t> io_bitmaps,
        gsl::not_null<exit_handler_t *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~io_instruction() final;

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
    /// Sets a '1' in the MSR bitmap corresponding with the provided port. All
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
    /// Sets a '1' in the MSR bitmap corresponding with all of the io_instruction. All
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
    /// Sets a '0' in the MSR bitmap corresponding with the provided port. All
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
    /// Sets a '0' in the MSR bitmap corresponding with all of the ports. All
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

    io_instruction(io_instruction &&) = default;
    io_instruction &operator=(io_instruction &&) = default;

    io_instruction(const io_instruction &) = delete;
    io_instruction &operator=(const io_instruction &) = delete;

    /// @endcond
};

}
}

#endif
