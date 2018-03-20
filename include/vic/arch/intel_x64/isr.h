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

#ifndef ISR_INTEL_X64_EAPIS_H
#define ISR_INTEL_X64_EAPIS_H

#include <bfvmm/hve/arch/x64/idt.h>

#include "base.h"

/// @cond

extern "C" EXPORT_SYM void
default_isr(
    uint64_t vector, uint64_t ec, bool ec_valid, uint64_t *regs) noexcept;

extern "C" void
set_default_isrs(
    bfvmm::x64::idt *idt, bfvmm::x64::idt::selector_type selector);

extern "C" void _isr0(void) noexcept;
extern "C" void _isr1(void) noexcept;
extern "C" void _isr2(void) noexcept;
extern "C" void _isr3(void) noexcept;
extern "C" void _isr4(void) noexcept;
extern "C" void _isr5(void) noexcept;
extern "C" void _isr6(void) noexcept;
extern "C" void _isr7(void) noexcept;
extern "C" void _isr8(void) noexcept;
extern "C" void _isr9(void) noexcept;
extern "C" void _isr10(void) noexcept;
extern "C" void _isr11(void) noexcept;
extern "C" void _isr12(void) noexcept;
extern "C" void _isr13(void) noexcept;
extern "C" void _isr14(void) noexcept;
extern "C" void _isr15(void) noexcept;
extern "C" void _isr16(void) noexcept;
extern "C" void _isr17(void) noexcept;
extern "C" void _isr18(void) noexcept;
extern "C" void _isr19(void) noexcept;
extern "C" void _isr20(void) noexcept;
extern "C" void _isr21(void) noexcept;
extern "C" void _isr22(void) noexcept;
extern "C" void _isr23(void) noexcept;
extern "C" void _isr24(void) noexcept;
extern "C" void _isr25(void) noexcept;
extern "C" void _isr26(void) noexcept;
extern "C" void _isr27(void) noexcept;
extern "C" void _isr28(void) noexcept;
extern "C" void _isr29(void) noexcept;
extern "C" void _isr30(void) noexcept;
extern "C" void _isr31(void) noexcept;
extern "C" void _isr32(void) noexcept;
extern "C" void _isr33(void) noexcept;
extern "C" void _isr34(void) noexcept;
extern "C" void _isr35(void) noexcept;
extern "C" void _isr36(void) noexcept;
extern "C" void _isr37(void) noexcept;
extern "C" void _isr38(void) noexcept;
extern "C" void _isr39(void) noexcept;
extern "C" void _isr40(void) noexcept;
extern "C" void _isr41(void) noexcept;
extern "C" void _isr42(void) noexcept;
extern "C" void _isr43(void) noexcept;
extern "C" void _isr44(void) noexcept;
extern "C" void _isr45(void) noexcept;
extern "C" void _isr46(void) noexcept;
extern "C" void _isr47(void) noexcept;
extern "C" void _isr48(void) noexcept;
extern "C" void _isr49(void) noexcept;
extern "C" void _isr50(void) noexcept;
extern "C" void _isr51(void) noexcept;
extern "C" void _isr52(void) noexcept;
extern "C" void _isr53(void) noexcept;
extern "C" void _isr54(void) noexcept;
extern "C" void _isr55(void) noexcept;
extern "C" void _isr56(void) noexcept;
extern "C" void _isr57(void) noexcept;
extern "C" void _isr58(void) noexcept;
extern "C" void _isr59(void) noexcept;
extern "C" void _isr60(void) noexcept;
extern "C" void _isr61(void) noexcept;
extern "C" void _isr62(void) noexcept;
extern "C" void _isr63(void) noexcept;
extern "C" void _isr64(void) noexcept;
extern "C" void _isr65(void) noexcept;
extern "C" void _isr66(void) noexcept;
extern "C" void _isr67(void) noexcept;
extern "C" void _isr68(void) noexcept;
extern "C" void _isr69(void) noexcept;
extern "C" void _isr70(void) noexcept;
extern "C" void _isr71(void) noexcept;
extern "C" void _isr72(void) noexcept;
extern "C" void _isr73(void) noexcept;
extern "C" void _isr74(void) noexcept;
extern "C" void _isr75(void) noexcept;
extern "C" void _isr76(void) noexcept;
extern "C" void _isr77(void) noexcept;
extern "C" void _isr78(void) noexcept;
extern "C" void _isr79(void) noexcept;
extern "C" void _isr80(void) noexcept;
extern "C" void _isr81(void) noexcept;
extern "C" void _isr82(void) noexcept;
extern "C" void _isr83(void) noexcept;
extern "C" void _isr84(void) noexcept;
extern "C" void _isr85(void) noexcept;
extern "C" void _isr86(void) noexcept;
extern "C" void _isr87(void) noexcept;
extern "C" void _isr88(void) noexcept;
extern "C" void _isr89(void) noexcept;
extern "C" void _isr90(void) noexcept;
extern "C" void _isr91(void) noexcept;
extern "C" void _isr92(void) noexcept;
extern "C" void _isr93(void) noexcept;
extern "C" void _isr94(void) noexcept;
extern "C" void _isr95(void) noexcept;
extern "C" void _isr96(void) noexcept;
extern "C" void _isr97(void) noexcept;
extern "C" void _isr98(void) noexcept;
extern "C" void _isr99(void) noexcept;
extern "C" void _isr100(void) noexcept;
extern "C" void _isr101(void) noexcept;
extern "C" void _isr102(void) noexcept;
extern "C" void _isr103(void) noexcept;
extern "C" void _isr104(void) noexcept;
extern "C" void _isr105(void) noexcept;
extern "C" void _isr106(void) noexcept;
extern "C" void _isr107(void) noexcept;
extern "C" void _isr108(void) noexcept;
extern "C" void _isr109(void) noexcept;
extern "C" void _isr110(void) noexcept;
extern "C" void _isr111(void) noexcept;
extern "C" void _isr112(void) noexcept;
extern "C" void _isr113(void) noexcept;
extern "C" void _isr114(void) noexcept;
extern "C" void _isr115(void) noexcept;
extern "C" void _isr116(void) noexcept;
extern "C" void _isr117(void) noexcept;
extern "C" void _isr118(void) noexcept;
extern "C" void _isr119(void) noexcept;
extern "C" void _isr120(void) noexcept;
extern "C" void _isr121(void) noexcept;
extern "C" void _isr122(void) noexcept;
extern "C" void _isr123(void) noexcept;
extern "C" void _isr124(void) noexcept;
extern "C" void _isr125(void) noexcept;
extern "C" void _isr126(void) noexcept;
extern "C" void _isr127(void) noexcept;
extern "C" void _isr128(void) noexcept;
extern "C" void _isr129(void) noexcept;
extern "C" void _isr130(void) noexcept;
extern "C" void _isr131(void) noexcept;
extern "C" void _isr132(void) noexcept;
extern "C" void _isr133(void) noexcept;
extern "C" void _isr134(void) noexcept;
extern "C" void _isr135(void) noexcept;
extern "C" void _isr136(void) noexcept;
extern "C" void _isr137(void) noexcept;
extern "C" void _isr138(void) noexcept;
extern "C" void _isr139(void) noexcept;
extern "C" void _isr140(void) noexcept;
extern "C" void _isr141(void) noexcept;
extern "C" void _isr142(void) noexcept;
extern "C" void _isr143(void) noexcept;
extern "C" void _isr144(void) noexcept;
extern "C" void _isr145(void) noexcept;
extern "C" void _isr146(void) noexcept;
extern "C" void _isr147(void) noexcept;
extern "C" void _isr148(void) noexcept;
extern "C" void _isr149(void) noexcept;
extern "C" void _isr150(void) noexcept;
extern "C" void _isr151(void) noexcept;
extern "C" void _isr152(void) noexcept;
extern "C" void _isr153(void) noexcept;
extern "C" void _isr154(void) noexcept;
extern "C" void _isr155(void) noexcept;
extern "C" void _isr156(void) noexcept;
extern "C" void _isr157(void) noexcept;
extern "C" void _isr158(void) noexcept;
extern "C" void _isr159(void) noexcept;
extern "C" void _isr160(void) noexcept;
extern "C" void _isr161(void) noexcept;
extern "C" void _isr162(void) noexcept;
extern "C" void _isr163(void) noexcept;
extern "C" void _isr164(void) noexcept;
extern "C" void _isr165(void) noexcept;
extern "C" void _isr166(void) noexcept;
extern "C" void _isr167(void) noexcept;
extern "C" void _isr168(void) noexcept;
extern "C" void _isr169(void) noexcept;
extern "C" void _isr170(void) noexcept;
extern "C" void _isr171(void) noexcept;
extern "C" void _isr172(void) noexcept;
extern "C" void _isr173(void) noexcept;
extern "C" void _isr174(void) noexcept;
extern "C" void _isr175(void) noexcept;
extern "C" void _isr176(void) noexcept;
extern "C" void _isr177(void) noexcept;
extern "C" void _isr178(void) noexcept;
extern "C" void _isr179(void) noexcept;
extern "C" void _isr180(void) noexcept;
extern "C" void _isr181(void) noexcept;
extern "C" void _isr182(void) noexcept;
extern "C" void _isr183(void) noexcept;
extern "C" void _isr184(void) noexcept;
extern "C" void _isr185(void) noexcept;
extern "C" void _isr186(void) noexcept;
extern "C" void _isr187(void) noexcept;
extern "C" void _isr188(void) noexcept;
extern "C" void _isr189(void) noexcept;
extern "C" void _isr190(void) noexcept;
extern "C" void _isr191(void) noexcept;
extern "C" void _isr192(void) noexcept;
extern "C" void _isr193(void) noexcept;
extern "C" void _isr194(void) noexcept;
extern "C" void _isr195(void) noexcept;
extern "C" void _isr196(void) noexcept;
extern "C" void _isr197(void) noexcept;
extern "C" void _isr198(void) noexcept;
extern "C" void _isr199(void) noexcept;
extern "C" void _isr200(void) noexcept;
extern "C" void _isr201(void) noexcept;
extern "C" void _isr202(void) noexcept;
extern "C" void _isr203(void) noexcept;
extern "C" void _isr204(void) noexcept;
extern "C" void _isr205(void) noexcept;
extern "C" void _isr206(void) noexcept;
extern "C" void _isr207(void) noexcept;
extern "C" void _isr208(void) noexcept;
extern "C" void _isr209(void) noexcept;
extern "C" void _isr210(void) noexcept;
extern "C" void _isr211(void) noexcept;
extern "C" void _isr212(void) noexcept;
extern "C" void _isr213(void) noexcept;
extern "C" void _isr214(void) noexcept;
extern "C" void _isr215(void) noexcept;
extern "C" void _isr216(void) noexcept;
extern "C" void _isr217(void) noexcept;
extern "C" void _isr218(void) noexcept;
extern "C" void _isr219(void) noexcept;
extern "C" void _isr220(void) noexcept;
extern "C" void _isr221(void) noexcept;
extern "C" void _isr222(void) noexcept;
extern "C" void _isr223(void) noexcept;
extern "C" void _isr224(void) noexcept;
extern "C" void _isr225(void) noexcept;
extern "C" void _isr226(void) noexcept;
extern "C" void _isr227(void) noexcept;
extern "C" void _isr228(void) noexcept;
extern "C" void _isr229(void) noexcept;
extern "C" void _isr230(void) noexcept;
extern "C" void _isr231(void) noexcept;
extern "C" void _isr232(void) noexcept;
extern "C" void _isr233(void) noexcept;
extern "C" void _isr234(void) noexcept;
extern "C" void _isr235(void) noexcept;
extern "C" void _isr236(void) noexcept;
extern "C" void _isr237(void) noexcept;
extern "C" void _isr238(void) noexcept;
extern "C" void _isr239(void) noexcept;
extern "C" void _isr240(void) noexcept;
extern "C" void _isr241(void) noexcept;
extern "C" void _isr242(void) noexcept;
extern "C" void _isr243(void) noexcept;
extern "C" void _isr244(void) noexcept;
extern "C" void _isr245(void) noexcept;
extern "C" void _isr246(void) noexcept;
extern "C" void _isr247(void) noexcept;
extern "C" void _isr248(void) noexcept;
extern "C" void _isr249(void) noexcept;
extern "C" void _isr250(void) noexcept;
extern "C" void _isr251(void) noexcept;
extern "C" void _isr252(void) noexcept;
extern "C" void _isr253(void) noexcept;
extern "C" void _isr254(void) noexcept;
extern "C" void _isr255(void) noexcept;

/// @endcond

#endif
