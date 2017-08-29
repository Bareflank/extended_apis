//
// Bareflank Hypervisor
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

#include <cstdlib>

#include <bftypes.h>
#include <bfdebug.h>
#include <bfexports.h>

#include <intrinsics/x86/intel_x64.h>

using namespace x64;
using namespace intel_x64;

extern "C" void unlock_write(void);

static auto
vector_to_str(uint64_t vector) noexcept
{
    switch(vector) {
        case 0x00: return "fault: divide by 0";
        case 0x01: return "fault/trap: debug exception";
        case 0x02: return "interrupt: nmi";
        case 0x03: return "trap: breakpoint";
        case 0x04: return "trap: overflow";
        case 0x05: return "fault: bound range exceeded";
        case 0x06: return "fault: invalid opcode";
        case 0x07: return "fault: device not available (no math coprocessor";
        case 0x08: return "abort: double fault";
        case 0x09: return "fault: coprocessor segment overrun";
        case 0x0A: return "fault: invalid TSS";
        case 0x0B: return "fault: segment not present";
        case 0x0C: return "fault: stack segment fault";
        case 0x0D: return "fault: general protection fault";
        case 0x0E: return "fault: page fault";
        case 0x10: return "fault: x87 fpu floating point error";
        case 0x11: return "fault: alignment check";
        case 0x12: return "abort: machine check";
        case 0x13: return "fault: simd floating point exception";
        case 0x14: return "fault: virtualization exception";
        default: return "undefined";
    }
}

extern "C" EXPORT_SYM void
isr_handler(
    uint64_t vector, uint64_t error_code, bool error_code_valid, uint64_t *regs) noexcept
{
    // NOTE:
    //
    // If the 'write' function throws a hardware exception, this function will
    // deadlock because it doesn't unlock the write mutex. If we end up with
    // stability issues with the debugging logic, we should modify the code
    // to detect when the same core attempts to get the lock, and unlock as
    // needed. For now, this case is unlikely, so it is ignored.
    //

    bfdebug_transaction(0, [&](std::string *msg) {
        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_lnbr(0, msg);
        bferror_brk1(0, msg);
        bferror_info(0, "VMM Panic!!!", msg);
        bferror_brk1(0, msg);

        if (vector == 0x0E && cr2::get() == 0) {
            bferror_info(0, "fault: null dereference", msg);
        }
        else {
            bferror_info(0, vector_to_str(vector), msg);
        }

        bferror_lnbr(0, msg);

        if (error_code_valid) {
            bferror_subnhex(0, "error code", error_code, msg);
        }

        auto view = gsl::span<uint64_t>(regs, 37);

        bferror_subnhex(0, "ss    ", view[36], msg);
        bferror_subnhex(0, "rsp   ", view[35], msg);
        bferror_subnhex(0, "rflags", view[34], msg);
        bferror_subnhex(0, "cs    ", view[33], msg);
        bferror_subnhex(0, "rip   ", view[32], msg);
        bferror_subnhex(0, "rax   ", view[14], msg);
        bferror_subnhex(0, "rbx   ", view[13], msg);
        bferror_subnhex(0, "rcx   ", view[12], msg);
        bferror_subnhex(0, "rdx   ", view[11], msg);
        bferror_subnhex(0, "rbp   ", view[10], msg);
        bferror_subnhex(0, "rsi   ", view[9], msg);
        bferror_subnhex(0, "rdi   ", view[8], msg);
        bferror_subnhex(0, "r8    ", view[7], msg);
        bferror_subnhex(0, "r9    ", view[6], msg);
        bferror_subnhex(0, "r10   ", view[5], msg);
        bferror_subnhex(0, "r11   ", view[4], msg);
        bferror_subnhex(0, "r12   ", view[3], msg);
        bferror_subnhex(0, "r13   ", view[2], msg);
        bferror_subnhex(0, "r14   ", view[1], msg);
        bferror_subnhex(0, "r15   ", view[0], msg);

        bferror_subnhex(0, "cr0   ", cr0::get(), msg);
        bferror_subnhex(0, "cr2   ", cr2::get(), msg);
        bferror_subnhex(0, "cr3   ", cr3::get(), msg);
        bferror_subnhex(0, "cr4   ", cr4::get(), msg);
    });

    pm::halt();
}
