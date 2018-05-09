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

#include <catch/catch.hpp>
#include <bfcapstone.h>
#include <bfvmm/hve/arch/intel_x64/save_state.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("capstone::read throws")
{
    bfvmm::intel_x64::save_state_t state;

    CHECK_THROWS(eapis::intel_x64::capstone::read8(&state, 0x088U));
    CHECK_THROWS(eapis::intel_x64::capstone::read16(&state, 0x087U));
    CHECK_THROWS(eapis::intel_x64::capstone::read32(&state, 0x085U));
    CHECK_THROWS(eapis::intel_x64::capstone::read64(&state, 0x081U));
}

TEST_CASE("eapis::intel_x64::capstone::read8")
{
    bfvmm::intel_x64::save_state_t state;
    state.rax = 0x7766554433221100U;

    CHECK(eapis::intel_x64::capstone::read8(&state, 0U) == 0x00U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 1U) == 0x11U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 2U) == 0x22U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 3U) == 0x33U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 4U) == 0x44U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 5U) == 0x55U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 6U) == 0x66U);
    CHECK(eapis::intel_x64::capstone::read8(&state, 7U) == 0x77U);
}

TEST_CASE("eapis::intel_x64::capstone::read16")
{
    bfvmm::intel_x64::save_state_t state;
    state.rax = 0x7766554433221100U;
    state.rbx = 0xFFU;

    CHECK(eapis::intel_x64::capstone::read16(&state, 7U) == 0xFF77U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 6U) == 0x7766U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 5U) == 0x6655U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 4U) == 0x5544U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 3U) == 0x4433U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 2U) == 0x3322U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 1U) == 0x2211U);
    CHECK(eapis::intel_x64::capstone::read16(&state, 0U) == 0x1100U);
}

TEST_CASE("eapis::intel_x64::capstone::read32")
{
    bfvmm::intel_x64::save_state_t state;
    state.rax = 0x7766554433221100U;
    state.rbx = 0x8899AABBCCDDEEFFU;

    CHECK(eapis::intel_x64::capstone::read32(&state, 12U) == 0x8899AABBU);
    CHECK(eapis::intel_x64::capstone::read32(&state, 11U) == 0x99AABBCCU);
    CHECK(eapis::intel_x64::capstone::read32(&state, 10U) == 0xAABBCCDDU);
    CHECK(eapis::intel_x64::capstone::read32(&state, 9U) == 0xBBCCDDEEU);
    CHECK(eapis::intel_x64::capstone::read32(&state, 8U) == 0xCCDDEEFFU);
    CHECK(eapis::intel_x64::capstone::read32(&state, 7U) == 0xDDEEFF77U);
    CHECK(eapis::intel_x64::capstone::read32(&state, 6U) == 0xEEFF7766U);
    CHECK(eapis::intel_x64::capstone::read32(&state, 5U) == 0xFF776655U);
}

TEST_CASE("eapis::intel_x64::capstone::read64")
{
    bfvmm::intel_x64::save_state_t state;
    state.rax = 0x7766554433221100U;
    state.rbx = 0x8899AABBCCDDEEFFU;
    state.rcx = 0x0U;

    CHECK(eapis::intel_x64::capstone::read64(&state, 16U) == 0x00U);
    CHECK(eapis::intel_x64::capstone::read64(&state, 15U) == 0x88U);
    CHECK(eapis::intel_x64::capstone::read64(&state, 14U) == 0x8899U);
    CHECK(eapis::intel_x64::capstone::read64(&state, 13U) == 0x8899AAU);
    CHECK(eapis::intel_x64::capstone::read64(&state, 12U) == 0x8899AABBU);
    CHECK(eapis::intel_x64::capstone::read64(&state, 11U) == 0x8899AABBCCU);
    CHECK(eapis::intel_x64::capstone::read64(&state, 10U) == 0x8899AABBCCDDU);
    CHECK(eapis::intel_x64::capstone::read64(&state, 9U) == 0x8899AABBCCDDEEU);
}

TEST_CASE("eapis::intel_x64::capstone::read_imm_val")
{
    bfvmm::intel_x64::save_state_t state;
    cs_x86_op op;

    op.type = X86_OP_IMM;
    op.imm = 0x42U;

    CHECK(eapis::intel_x64::capstone::read_imm_val(&state, &op) == 0x42U);
}

TEST_CASE("eapis::intel_x64::capstone::read_reg_val")
{
    bfvmm::intel_x64::save_state_t state;
    cs_x86_op op;

    state.rax = 0x7766554433221100U;
    op.type = X86_OP_REG;

    op.reg = X86_REG_AH;
    CHECK(eapis::intel_x64::capstone::read_reg_val(&state, &op) == 0x11U);

    op.reg = X86_REG_AX;
    CHECK(eapis::intel_x64::capstone::read_reg_val(&state, &op) == 0x1100U);

    op.reg = X86_REG_EAX;
    CHECK(eapis::intel_x64::capstone::read_reg_val(&state, &op) == 0x33221100U);

    op.reg = X86_REG_RAX;
    CHECK(eapis::intel_x64::capstone::read_reg_val(&state, &op) == state.rax);
}

TEST_CASE("eapis::intel_x64::capstone::read_mem_val")
{
    bfvmm::intel_x64::save_state_t state;
    cs_x86_op op;

    op.type = X86_OP_MEM;
    CHECK_THROWS(eapis::intel_x64::capstone::read_mem_val(&state, &op));
}

TEST_CASE("eapis::intel_x64::capstone::read_op_val")
{
    bfvmm::intel_x64::save_state_t state;
    cs_insn insn;

    insn.detail = reinterpret_cast<cs_detail *>(malloc(sizeof(cs_detail)));
    if (insn.detail == nullptr) {
        CHECK(false);
    }

    insn.detail->x86.op_count = 1U;
    CHECK_THROWS(eapis::intel_x64::capstone::read_op_val(&state, &insn, 1U));

    insn.detail->x86.operands[0U].type = X86_OP_IMM;
    CHECK_NOTHROW(eapis::intel_x64::capstone::read_op_val(&state, &insn, 0U));

    insn.detail->x86.operands[0U].type = X86_OP_REG;
    insn.detail->x86.operands[0U].reg = X86_REG_EAX;
    CHECK_NOTHROW(eapis::intel_x64::capstone::read_op_val(&state, &insn, 0U));

    insn.detail->x86.operands[0U].type = X86_OP_MEM;
    CHECK_THROWS(eapis::intel_x64::capstone::read_op_val(&state, &insn, 0U));

    uint8_t *err_ptr = reinterpret_cast<uint8_t *>(insn.detail->x86.operands);
    *err_ptr = 0xFFU;
    CHECK_THROWS(eapis::intel_x64::capstone::read_op_val(&state, &insn, 0U));

    free(insn.detail);
}

#endif
