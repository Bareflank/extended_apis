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

#include <bfdebug.h>
#include <hve/arch/intel_x64/io_instruction.h>

#include <bfvmm/memory_manager/arch/x64/map_ptr.h>

namespace eapis
{
namespace intel_x64
{

io_instruction::io_instruction(
    gsl::span<uint8_t> io_bitmaps,
    gsl::not_null<exit_handler_t *> exit_handler
) :
    m_io_bitmaps{io_bitmaps},
    m_exit_handler{exit_handler}
{
    using namespace vmcs_n;

    m_exit_handler->add_handler(
        exit_reason::basic_exit_reason::io_instruction,
        ::handler_delegate_t::create<io_instruction, &io_instruction::handle>(this)
    );
}

io_instruction::~io_instruction()
{
    if (!ndebug && m_log_enabled) {
        dump_log();
    }
}

// -----------------------------------------------------------------------------
// RDMSR
// -----------------------------------------------------------------------------

void
io_instruction::add_handler(
    vmcs_n::value_type port, handler_delegate_t &&in_d, handler_delegate_t &&out_d)
{
    trap_on_access(port);

    m_in_handlers[port].push_front(std::move(in_d));
    m_out_handlers[port].push_front(std::move(out_d));
}

void
io_instruction::trap_on_access(vmcs_n::value_type port)
{
    if (port < 0x10000) {
        set_bit(m_io_bitmaps, port);
        return;
    }

    throw std::runtime_error("invalid port: " + std::to_string(port));
}

void
io_instruction::trap_on_all_accesses()
{ gsl::memset(m_io_bitmaps, 0xFF); }

void
io_instruction::pass_through_access(vmcs_n::value_type port)
{
    if (port < 0x10000) {
        clear_bit(m_io_bitmaps, port);
        return;
    }

    throw std::runtime_error("invalid port: " + std::to_string(port));
}

void
io_instruction::pass_through_all_accesses()
{ gsl::memset(m_io_bitmaps, 0x0); }

// -----------------------------------------------------------------------------
// Debug
// -----------------------------------------------------------------------------

void
io_instruction::dump_log()
{
    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_info(0, "io instruction log", msg);
        bfdebug_brk2(0, msg);

        for (const auto &record : m_log) {
            bfdebug_info(0, "record", msg);
            bfdebug_subnhex(0, "port_number", record.port_number, msg);
            bfdebug_subnhex(0, "size_of_access", record.size_of_access, msg);
            bfdebug_subnhex(0, "direction_of_access", record.direction_of_access, msg);
            bfdebug_subnhex(0, "address", record.address, msg);
            bfdebug_subnhex(0, "val", record.val, msg);
        }

        bfdebug_lnbr(0, msg);
    });
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
io_instruction::handle(gsl::not_null<vmcs_t *> vmcs)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;
    auto eq = io_instruction::get();

    auto reps = 1ULL;
    if (io_instruction::rep_prefixed::is_enabled(eq)) {
        reps = vmcs->save_state()->rcx & 0x00000000FFFFFFFF;
    }

    struct info_t info = {
        0,
        io_instruction::size_of_access::get(eq),
        0,
        0,
        false,
        false
    };

    switch(io_instruction::operand_encoding::get(eq)) {
        case io_instruction::operand_encoding::dx:
            info.port_number = vmcs->save_state()->rdx & 0x000000000000FFFF;
            break;

        default:
            info.port_number = io_instruction::port_number::get(eq);
            break;
    }

    if (io_instruction::string_instruction::is_enabled(eq)) {
        info.address = vmcs_n::guest_linear_address::get();
    }

    for (auto i = 0ULL; i < reps; i++) {
        switch(io_instruction::direction_of_access::get(eq)) {
            case io_instruction::direction_of_access::in:
                handle_in(vmcs, info);
                break;

            default:
                handle_out(vmcs, info);
                break;
        }

        info.address += info.size_of_access;
    }

    return true;
}

bool
io_instruction::handle_in(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    const auto &hdlrs =
        m_in_handlers.find(info.port_number);

    if (GSL_LIKELY(hdlrs != m_in_handlers.end())) {
        emulate_in(info);

        if (!ndebug && m_log_enabled) {
            add_record(m_log, {
                info.port_number,
                info.size_of_access,
                io_instruction::direction_of_access::in,
                info.address,
                info.val
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    store_operand(vmcs, info);
                }

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

    throw std::runtime_error(
        "io_instruction::handle_in: unhandled io instruction #" + std::to_string(info.port_number));
}

bool
io_instruction::handle_out(gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    const auto &hdlrs =
        m_in_handlers.find(info.port_number);

    if (GSL_LIKELY(hdlrs != m_in_handlers.end())) {
        load_operand(vmcs, info);

        if (!ndebug && m_log_enabled) {
            add_record(m_log, {
                info.port_number,
                info.size_of_access,
                io_instruction::direction_of_access::out,
                info.address,
                info.val
            });
        }

        for (const auto &d : hdlrs->second) {
            if (d(vmcs, info)) {

                if (!info.ignore_write) {
                    emulate_out(info);
                }

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }

    throw std::runtime_error(
        "io_instruction::handle_out: unhandled io instruction #" + std::to_string(info.port_number));
}

void
io_instruction::emulate_in(info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    switch(info.size_of_access) {
        case io_instruction::size_of_access::one_byte:
            info.val = ::x64::portio::inb(gsl::narrow_cast<uint16_t>(info.port_number));
            break;

        case io_instruction::size_of_access::two_byte:
            info.val = ::x64::portio::inw(gsl::narrow_cast<uint16_t>(info.port_number));
            break;

        default:
            info.val = ::x64::portio::ind(gsl::narrow_cast<uint16_t>(info.port_number));
            break;
    }
}

void
io_instruction::emulate_out(info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    switch(info.size_of_access) {
        case io_instruction::size_of_access::one_byte:
            ::x64::portio::outb(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint8_t>(info.val)
            );
            break;

        case io_instruction::size_of_access::two_byte:
            ::x64::portio::outw(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint16_t>(info.val)
            );
            break;

        default:
            ::x64::portio::outd(
                gsl::narrow_cast<uint16_t>(info.port_number),
                gsl::narrow_cast<uint32_t>(info.val)
            );
            break;
    }
}

void
io_instruction::load_operand(
    gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    if (info.address != 0) {
        switch(info.size_of_access) {
            case io_instruction::size_of_access::one_byte: {
                auto map = bfvmm::x64::make_unique_map<uint8_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                info.val = map.get()[0] & 0x00000000000000FF;
                break;
            }

            case io_instruction::size_of_access::two_byte: {
                auto map = bfvmm::x64::make_unique_map<uint16_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                info.val = map.get()[0] & 0x000000000000FFFF;
                break;
            }

            default: {
                auto map = bfvmm::x64::make_unique_map<uint32_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                info.val = map.get()[0] & 0x00000000FFFFFFFF;
                break;
            }
        }
    }
    else {
        switch(info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                info.val = vmcs->save_state()->rax & 0x00000000000000FF;
                break;

            case io_instruction::size_of_access::two_byte:
                info.val = vmcs->save_state()->rax & 0x000000000000FFFF;
                break;

            default:
                info.val = vmcs->save_state()->rax & 0x00000000FFFFFFFF;
                break;
        }
    }
}

void
io_instruction::store_operand(
    gsl::not_null<vmcs_t *> vmcs, info_t &info)
{
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    if (info.address != 0) {
        switch(info.size_of_access) {
            case io_instruction::size_of_access::one_byte: {
                auto map = bfvmm::x64::make_unique_map<uint8_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                map.get()[0] = gsl::narrow_cast<uint8_t>(info.val);
                break;
            }

            case io_instruction::size_of_access::two_byte: {
                auto map = bfvmm::x64::make_unique_map<uint16_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                map.get()[0] = gsl::narrow_cast<uint16_t>(info.val);
                break;
            }

            default: {
                auto map = bfvmm::x64::make_unique_map<uint32_t>(
                    info.address, vmcs_n::guest_cr3::get(),
                    info.size_of_access, vmcs_n::guest_ia32_pat::get()
                );

                map.get()[0] = gsl::narrow_cast<uint32_t>(info.val);
                break;
            }
        }
    }
    else {
        switch(info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                vmcs->save_state()->rax = set_bits(
                    vmcs->save_state()->rax, 0x00000000000000FF, info.val);
                break;

            case io_instruction::size_of_access::two_byte:
                vmcs->save_state()->rax = set_bits(
                    vmcs->save_state()->rax, 0x000000000000FFFF, info.val);
                break;

            default:
                vmcs->save_state()->rax = set_bits(
                    vmcs->save_state()->rax, 0x00000000FFFFFFFF, info.val);
                break;
        }
    }
}

}
}
