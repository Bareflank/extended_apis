//
// Bareflank Extended APIs
//
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

#ifndef ESR_INTEL_X64_EAPIS_H
#define ESR_INTEL_X64_EAPIS_H

#include "base.h"

/// @cond

extern const char *
vector_to_str(uint64_t vec) noexcept;

extern "C" EXPORT_SYM void
default_esr(
    uint64_t vector, uint64_t ec, bool ec_valid, uint64_t *regs) noexcept;

extern "C" void
set_default_esrs(
    bfvmm::x64::idt *idt, bfvmm::x64::idt::selector_type selector);

namespace eapis
{
namespace intel_x64
{
namespace exception
{
    constexpr const auto de = 0U;
    constexpr const auto db = 1U;
    constexpr const auto bp = 3U;
    constexpr const auto of = 4U;
    constexpr const auto br = 5U;
    constexpr const auto ud = 6U;
    constexpr const auto nm = 7U;
    constexpr const auto df = 8U;
    constexpr const auto ts = 10U;
    constexpr const auto np = 11U;
    constexpr const auto ss = 12U;
    constexpr const auto gp = 13U;
    constexpr const auto pf = 14U;
    constexpr const auto mf = 16U;
    constexpr const auto ac = 17U;
    constexpr const auto mc = 18U;
    constexpr const auto xm = 19U;
    constexpr const auto ve = 20U;
}
}
}

extern "C" void _esr0(void) noexcept;
extern "C" void _esr1(void) noexcept;
extern "C" void _esr2(void) noexcept;
extern "C" void _esr3(void) noexcept;
extern "C" void _esr4(void) noexcept;
extern "C" void _esr5(void) noexcept;
extern "C" void _esr6(void) noexcept;
extern "C" void _esr7(void) noexcept;
extern "C" void _esr8(void) noexcept;
extern "C" void _esr9(void) noexcept;
extern "C" void _esr10(void) noexcept;
extern "C" void _esr11(void) noexcept;
extern "C" void _esr12(void) noexcept;
extern "C" void _esr13(void) noexcept;
extern "C" void _esr14(void) noexcept;
extern "C" void _esr15(void) noexcept;
extern "C" void _esr16(void) noexcept;
extern "C" void _esr17(void) noexcept;
extern "C" void _esr18(void) noexcept;
extern "C" void _esr19(void) noexcept;
extern "C" void _esr20(void) noexcept;
extern "C" void _esr21(void) noexcept;
extern "C" void _esr22(void) noexcept;
extern "C" void _esr23(void) noexcept;
extern "C" void _esr24(void) noexcept;
extern "C" void _esr25(void) noexcept;
extern "C" void _esr26(void) noexcept;
extern "C" void _esr27(void) noexcept;
extern "C" void _esr28(void) noexcept;
extern "C" void _esr29(void) noexcept;
extern "C" void _esr30(void) noexcept;
extern "C" void _esr31(void) noexcept;

/// @endcond

#endif
