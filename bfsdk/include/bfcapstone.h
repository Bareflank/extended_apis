//
// Bareflank Hypervisor
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

#ifndef BFCAPSTONE_INTEL_X64_H
#define BFCAPSTONE_INTEL_X64_H

#include <unordered_map>
#include <intrinsics.h>
#include <capstone/capstone.h>
#include <bfvmm/hve/arch/intel_x64/save_state.h>

namespace eapis
{
namespace intel_x64
{

namespace vmcs_n = ::intel_x64::vmcs;

namespace capstone
{
    enum reg_width : uint64_t {
        byte = 1U,
        word = 2U,
        dword = 4U,
        qword = 8U
    };

    struct reg {
        enum x86_reg id;
        enum reg_width width;
        uint64_t byte_offset;
    };

    constexpr struct reg al = { X86_REG_AL, byte, 0x0U };
    constexpr struct reg ah = { X86_REG_AH, byte, 0x1U };
    constexpr struct reg ax = { X86_REG_AX, word, 0x0U };
    constexpr struct reg eax = { X86_REG_EAX, dword, 0x0U };
    constexpr struct reg rax = { X86_REG_RAX, qword, 0x0U };

    constexpr struct reg bl = { X86_REG_BL, byte, 0x8U };
    constexpr struct reg bh = { X86_REG_BH, byte, 0x9U };
    constexpr struct reg bx = { X86_REG_BX, word, 0x8U };
    constexpr struct reg ebx = { X86_REG_EBX, dword, 0x8U };
    constexpr struct reg rbx = { X86_REG_RBX, qword, 0x8U };

    constexpr struct reg cl = { X86_REG_CL, byte, 0x10U };
    constexpr struct reg ch = { X86_REG_CH, byte, 0x11U };
    constexpr struct reg cx = { X86_REG_CX, word, 0x10U };
    constexpr struct reg ecx = { X86_REG_ECX, dword, 0x10U };
    constexpr struct reg rcx = { X86_REG_RCX, qword, 0x10U };

    constexpr struct reg dl = { X86_REG_DL, byte, 0x18U };
    constexpr struct reg dh = { X86_REG_DH, byte, 0x19U };
    constexpr struct reg dx = { X86_REG_DX, word, 0x18U };
    constexpr struct reg edx = { X86_REG_EDX, dword, 0x18U };
    constexpr struct reg rdx = { X86_REG_RDX, qword, 0x18U };

    constexpr struct reg bp = { X86_REG_BP, word, 0x20U };
    constexpr struct reg ebp = { X86_REG_EBP, dword, 0x20U };
    constexpr struct reg rbp = { X86_REG_RBP, qword, 0x20U };

    constexpr struct reg si = { X86_REG_SI, word, 0x28U };
    constexpr struct reg esi = { X86_REG_ESI, dword, 0x28U };
    constexpr struct reg rsi = { X86_REG_RSI, qword, 0x28U };

    constexpr struct reg di = { X86_REG_DI, word, 0x30U };
    constexpr struct reg edi = { X86_REG_EDI, dword, 0x30U };
    constexpr struct reg rdi = { X86_REG_RDI, qword, 0x30U };

    constexpr struct reg r08 = { X86_REG_R8, qword, 0x38U };
    constexpr struct reg r09 = { X86_REG_R9, qword, 0x40U };
    constexpr struct reg r10 = { X86_REG_R10, qword, 0x48U };
    constexpr struct reg r11 = { X86_REG_R11, qword, 0x50U };
    constexpr struct reg r12 = { X86_REG_R12, qword, 0x58U };
    constexpr struct reg r13 = { X86_REG_R13, qword, 0x60U };
    constexpr struct reg r14 = { X86_REG_R14, qword, 0x68U };
    constexpr struct reg r15 = { X86_REG_R15, qword, 0x70U };

    constexpr struct reg ip = { X86_REG_IP, word, 0x78U };
    constexpr struct reg eip = { X86_REG_EIP, dword, 0x78U };
    constexpr struct reg rip = { X86_REG_RIP, qword, 0x78U };

    constexpr struct reg sp = { X86_REG_SP, word, 0x80U };
    constexpr struct reg esp = { X86_REG_ESP, dword, 0x80U };
    constexpr struct reg rsp = { X86_REG_RSP, qword, 0x80U };

    const std::unordered_map<enum x86_reg, struct reg> reg_map = {
        {al.id, al},
        {ah.id, ah},
        {ax.id, ax},
        {eax.id, eax},
        {rax.id, rax},

        {bl.id, bl},
        {bh.id, bh},
        {bx.id, bx},
        {ebx.id, ebx},
        {rbx.id, rbx},

        {cl.id, cl},
        {ch.id, ch},
        {cx.id, cx},
        {ecx.id, ecx},
        {rcx.id, rcx},

        {dl.id, dl},
        {dh.id, dh},
        {dx.id, dx},
        {edx.id, edx},
        {rdx.id, rdx},

        {bp.id, bp},
        {ebp.id, ebp},
        {rbp.id, rbp},

        {si.id, si},
        {esi.id, esi},
        {rsi.id, rsi},

        {di.id, di},
        {edi.id, edi},
        {rdi.id, rdi},

        {r08.id, r08},
        {r09.id, r09},
        {r10.id, r10},
        {r11.id, r11},
        {r12.id, r12},
        {r13.id, r13},
        {r14.id, r14},
        {r15.id, r15},

        {ip.id, ip},
        {eip.id, eip},
        {rip.id, rip},

        {sp.id, sp},
        {esp.id, esp},
        {rsp.id, rsp}
    };

    using bfvmm::intel_x64::save_state_t;

    inline uint8_t read8(const save_state_t *state, uint64_t byte_offset)
    {
        expects(byte_offset < 0x88U);
        auto addr = reinterpret_cast<const uintptr_t>(state) + byte_offset;
        return *reinterpret_cast<const uint8_t *>(addr);
    }

    inline uint16_t read16(const save_state_t *state, uint64_t byte_offset)
    {
        expects(byte_offset <= 0x86U);
        auto addr = reinterpret_cast<const uintptr_t>(state) + byte_offset;
        return *reinterpret_cast<const uint16_t *>(addr);
    }

    inline uint32_t read32(const save_state_t *state, uint64_t byte_offset)
    {
        expects(byte_offset <= 0x84U);
        auto addr = reinterpret_cast<const uintptr_t>(state) + byte_offset;
        return *reinterpret_cast<const uint32_t *>(addr);
    }

    inline uint64_t read64(const save_state_t *state, uint64_t byte_offset)
    {
        expects(byte_offset <= 0x80U);
        auto addr = reinterpret_cast<const uintptr_t>(state) + byte_offset;
        return *reinterpret_cast<const uint64_t *>(addr);
    }

    /// We return unsigned here because this function is intended
    /// to be used with unsigned values, like xAPIC regs. The name
    /// should probably be changed reflect this.
    inline uint64_t read_imm_val(const save_state_t *state, const cs_x86_op *op)
    { return static_cast<uint64_t>(op->imm); }

    inline uint64_t read_reg_val(const save_state_t *state, const cs_x86_op *op)
    {
        const auto reg = reg_map.at(op->reg);

        switch (reg.width) {
            case qword: return read64(state, reg.byte_offset);
            case dword: return read32(state, reg.byte_offset);
            case word: return read16(state, reg.byte_offset);
            case byte: return read8(state, reg.byte_offset);

            default:
                throw std::invalid_argument(
                "invalid capstone::reg width: " + std::to_string(reg.width));
        }
    }

    inline uint64_t read_mem_val(const save_state_t *state, const cs_x86_op *op)
    {
        bfalert_info(0, "read_mem_value");
        bfdebug_nhex(0, "op->mem.segment", op->mem.segment);
        bfdebug_nhex(0, "op->mem.base", op->mem.base);
        bfdebug_nhex(0, "op->mem.index", op->mem.index);
        bfdebug_nhex(0, "op->mem.scale", op->mem.scale);
        bfdebug_nhex(0, "op->mem.disp", op->mem.disp);

        throw std::runtime_error("capstone: unexpected mem read");
     }

    inline uint64_t read_op_val(
        const save_state_t *state, const cs_insn *insn, size_t op_index)
    {
        expects(op_index < insn->detail->x86.op_count);

        const auto op = &insn->detail->x86.operands[op_index];
        const auto type = static_cast<uint64_t>(op->type);

        switch (type) {
            case X86_OP_IMM: return read_imm_val(state, op);
            case X86_OP_REG: return read_reg_val(state, op);
            case X86_OP_MEM: return read_mem_val(state, op);

            default:
                throw std::runtime_error(
                "unexpected capstone op.type: " + std::to_string(type));
        }
    }

    /// @endcond
}
}
}

#endif
