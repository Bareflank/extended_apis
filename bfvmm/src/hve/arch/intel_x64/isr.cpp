//
// Bareflank Hypervisor
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

#include <cstdlib>

#include <hve/arch/intel_x64/isr.h>
#include <hve/arch/intel_x64/vic.h>

extern "C" void unlock_write(void);

const char*
vector_to_str(uint64_t vec) noexcept
{
    switch (vec) {
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
default_isr(uint64_t vec, uint64_t ec, bool ec_valid, uint64_t *reg) noexcept
{
    if (vec >= 0x20U) {
        auto vic = reinterpret_cast<eapis::intel_x64::vic *>(*reg);
        vic->handle_interrupt(vec);
    }
    else {

        // NOTE:
        //
        // If the 'write' function throws a hardware exception, this function will
        // deadlock because it doesn't unlock the write mutex. If we end up with
        // stability issues with the debugging logic, we should modify the code
        // to detect when the same core attempts to get the lock, and unlock as
        // needed. For now, this case is unlikely, so it is ignored.
        //

        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_lnbr(0, msg);
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, "VMM Panic!!!", msg);
            bferror_brk1(0, msg);

            if (vec == 0x0E && ::intel_x64::cr2::get() == 0) {
                bferror_info(0, "fault: null dereference", msg);
            }
            else {
                bferror_info(0, vector_to_str(vec), msg);
            }

            bferror_lnbr(0, msg);

            if (ec_valid) {
                bferror_subnhex(0, "error code", ec, msg);
            }

            auto view = gsl::span<uint64_t>(reg, 38);

            bferror_subnhex(0, "ss    ", view[37], msg);
            bferror_subnhex(0, "rsp   ", view[36], msg);
            bferror_subnhex(0, "rflags", view[35], msg);
            bferror_subnhex(0, "cs    ", view[34], msg);
            bferror_subnhex(0, "rip   ", view[33], msg);
            bferror_subnhex(0, "rax   ", view[15], msg);
            bferror_subnhex(0, "rbx   ", view[14], msg);
            bferror_subnhex(0, "rcx   ", view[13], msg);
            bferror_subnhex(0, "rdx   ", view[12], msg);
            bferror_subnhex(0, "rbp   ", view[11], msg);
            bferror_subnhex(0, "rsi   ", view[10], msg);
            bferror_subnhex(0, "rdi   ", view[9], msg);
            bferror_subnhex(0, "r8    ", view[8], msg);
            bferror_subnhex(0, "r9    ", view[7], msg);
            bferror_subnhex(0, "r10   ", view[6], msg);
            bferror_subnhex(0, "r11   ", view[5], msg);
            bferror_subnhex(0, "r12   ", view[4], msg);
            bferror_subnhex(0, "r13   ", view[3], msg);
            bferror_subnhex(0, "r14   ", view[2], msg);
            bferror_subnhex(0, "r15   ", view[1], msg);
            bferror_subnhex(0, "vic   ", view[0], msg);

            bferror_subnhex(0, "cr0   ", ::intel_x64::cr0::get(), msg);
            bferror_subnhex(0, "cr2   ", ::intel_x64::cr2::get(), msg);
            bferror_subnhex(0, "cr3   ", ::intel_x64::cr3::get(), msg);
            bferror_subnhex(0, "cr4   ", ::intel_x64::cr4::get(), msg);
        });

        ::x64::pm::halt();
    }
}

// -----------------------------------------------------------------------------
// Populate the IDT entries
// -----------------------------------------------------------------------------

void set_default_isrs(
    bfvmm::x64::idt *idt,
    bfvmm::x64::idt::selector_type selector)
{
    idt->set(0, _isr0, selector);
    idt->set(1, _isr1, selector);
    idt->set(2, _isr2, selector);
    idt->set(3, _isr3, selector);
    idt->set(4, _isr4, selector);
    idt->set(5, _isr5, selector);
    idt->set(6, _isr6, selector);
    idt->set(7, _isr7, selector);
    idt->set(8, _isr8, selector);
    idt->set(9, _isr9, selector);
    idt->set(10, _isr10, selector);
    idt->set(11, _isr11, selector);
    idt->set(12, _isr12, selector);
    idt->set(13, _isr13, selector);
    idt->set(14, _isr14, selector);
    idt->set(15, _isr15, selector);
    idt->set(16, _isr16, selector);
    idt->set(17, _isr17, selector);
    idt->set(18, _isr18, selector);
    idt->set(19, _isr19, selector);
    idt->set(20, _isr20, selector);
    idt->set(21, _isr21, selector);
    idt->set(22, _isr22, selector);
    idt->set(23, _isr23, selector);
    idt->set(24, _isr24, selector);
    idt->set(25, _isr25, selector);
    idt->set(26, _isr26, selector);
    idt->set(27, _isr27, selector);
    idt->set(28, _isr28, selector);
    idt->set(29, _isr29, selector);
    idt->set(30, _isr30, selector);
    idt->set(31, _isr31, selector);
    idt->set(32, _isr32, selector);
    idt->set(33, _isr33, selector);
    idt->set(34, _isr34, selector);
    idt->set(35, _isr35, selector);
    idt->set(36, _isr36, selector);
    idt->set(37, _isr37, selector);
    idt->set(38, _isr38, selector);
    idt->set(39, _isr39, selector);
    idt->set(40, _isr40, selector);
    idt->set(41, _isr41, selector);
    idt->set(42, _isr42, selector);
    idt->set(43, _isr43, selector);
    idt->set(44, _isr44, selector);
    idt->set(45, _isr45, selector);
    idt->set(46, _isr46, selector);
    idt->set(47, _isr47, selector);
    idt->set(48, _isr48, selector);
    idt->set(49, _isr49, selector);
    idt->set(50, _isr50, selector);
    idt->set(51, _isr51, selector);
    idt->set(52, _isr52, selector);
    idt->set(53, _isr53, selector);
    idt->set(54, _isr54, selector);
    idt->set(55, _isr55, selector);
    idt->set(56, _isr56, selector);
    idt->set(57, _isr57, selector);
    idt->set(58, _isr58, selector);
    idt->set(59, _isr59, selector);
    idt->set(60, _isr60, selector);
    idt->set(61, _isr61, selector);
    idt->set(62, _isr62, selector);
    idt->set(63, _isr63, selector);
    idt->set(64, _isr64, selector);
    idt->set(65, _isr65, selector);
    idt->set(66, _isr66, selector);
    idt->set(67, _isr67, selector);
    idt->set(68, _isr68, selector);
    idt->set(69, _isr69, selector);
    idt->set(70, _isr70, selector);
    idt->set(71, _isr71, selector);
    idt->set(72, _isr72, selector);
    idt->set(73, _isr73, selector);
    idt->set(74, _isr74, selector);
    idt->set(75, _isr75, selector);
    idt->set(76, _isr76, selector);
    idt->set(77, _isr77, selector);
    idt->set(78, _isr78, selector);
    idt->set(79, _isr79, selector);
    idt->set(80, _isr80, selector);
    idt->set(81, _isr81, selector);
    idt->set(82, _isr82, selector);
    idt->set(83, _isr83, selector);
    idt->set(84, _isr84, selector);
    idt->set(85, _isr85, selector);
    idt->set(86, _isr86, selector);
    idt->set(87, _isr87, selector);
    idt->set(88, _isr88, selector);
    idt->set(89, _isr89, selector);
    idt->set(90, _isr90, selector);
    idt->set(91, _isr91, selector);
    idt->set(92, _isr92, selector);
    idt->set(93, _isr93, selector);
    idt->set(94, _isr94, selector);
    idt->set(95, _isr95, selector);
    idt->set(96, _isr96, selector);
    idt->set(97, _isr97, selector);
    idt->set(98, _isr98, selector);
    idt->set(99, _isr99, selector);
    idt->set(100, _isr100, selector);
    idt->set(101, _isr101, selector);
    idt->set(102, _isr102, selector);
    idt->set(103, _isr103, selector);
    idt->set(104, _isr104, selector);
    idt->set(105, _isr105, selector);
    idt->set(106, _isr106, selector);
    idt->set(107, _isr107, selector);
    idt->set(108, _isr108, selector);
    idt->set(109, _isr109, selector);
    idt->set(110, _isr110, selector);
    idt->set(111, _isr111, selector);
    idt->set(112, _isr112, selector);
    idt->set(113, _isr113, selector);
    idt->set(114, _isr114, selector);
    idt->set(115, _isr115, selector);
    idt->set(116, _isr116, selector);
    idt->set(117, _isr117, selector);
    idt->set(118, _isr118, selector);
    idt->set(119, _isr119, selector);
    idt->set(120, _isr120, selector);
    idt->set(121, _isr121, selector);
    idt->set(122, _isr122, selector);
    idt->set(123, _isr123, selector);
    idt->set(124, _isr124, selector);
    idt->set(125, _isr125, selector);
    idt->set(126, _isr126, selector);
    idt->set(127, _isr127, selector);
    idt->set(128, _isr128, selector);
    idt->set(129, _isr129, selector);
    idt->set(130, _isr130, selector);
    idt->set(131, _isr131, selector);
    idt->set(132, _isr132, selector);
    idt->set(133, _isr133, selector);
    idt->set(134, _isr134, selector);
    idt->set(135, _isr135, selector);
    idt->set(136, _isr136, selector);
    idt->set(137, _isr137, selector);
    idt->set(138, _isr138, selector);
    idt->set(139, _isr139, selector);
    idt->set(140, _isr140, selector);
    idt->set(141, _isr141, selector);
    idt->set(142, _isr142, selector);
    idt->set(143, _isr143, selector);
    idt->set(144, _isr144, selector);
    idt->set(145, _isr145, selector);
    idt->set(146, _isr146, selector);
    idt->set(147, _isr147, selector);
    idt->set(148, _isr148, selector);
    idt->set(149, _isr149, selector);
    idt->set(150, _isr150, selector);
    idt->set(151, _isr151, selector);
    idt->set(152, _isr152, selector);
    idt->set(153, _isr153, selector);
    idt->set(154, _isr154, selector);
    idt->set(155, _isr155, selector);
    idt->set(156, _isr156, selector);
    idt->set(157, _isr157, selector);
    idt->set(158, _isr158, selector);
    idt->set(159, _isr159, selector);
    idt->set(160, _isr160, selector);
    idt->set(161, _isr161, selector);
    idt->set(162, _isr162, selector);
    idt->set(163, _isr163, selector);
    idt->set(164, _isr164, selector);
    idt->set(165, _isr165, selector);
    idt->set(166, _isr166, selector);
    idt->set(167, _isr167, selector);
    idt->set(168, _isr168, selector);
    idt->set(169, _isr169, selector);
    idt->set(170, _isr170, selector);
    idt->set(171, _isr171, selector);
    idt->set(172, _isr172, selector);
    idt->set(173, _isr173, selector);
    idt->set(174, _isr174, selector);
    idt->set(175, _isr175, selector);
    idt->set(176, _isr176, selector);
    idt->set(177, _isr177, selector);
    idt->set(178, _isr178, selector);
    idt->set(179, _isr179, selector);
    idt->set(180, _isr180, selector);
    idt->set(181, _isr181, selector);
    idt->set(182, _isr182, selector);
    idt->set(183, _isr183, selector);
    idt->set(184, _isr184, selector);
    idt->set(185, _isr185, selector);
    idt->set(186, _isr186, selector);
    idt->set(187, _isr187, selector);
    idt->set(188, _isr188, selector);
    idt->set(189, _isr189, selector);
    idt->set(190, _isr190, selector);
    idt->set(191, _isr191, selector);
    idt->set(192, _isr192, selector);
    idt->set(193, _isr193, selector);
    idt->set(194, _isr194, selector);
    idt->set(195, _isr195, selector);
    idt->set(196, _isr196, selector);
    idt->set(197, _isr197, selector);
    idt->set(198, _isr198, selector);
    idt->set(199, _isr199, selector);
    idt->set(200, _isr200, selector);
    idt->set(201, _isr201, selector);
    idt->set(202, _isr202, selector);
    idt->set(203, _isr203, selector);
    idt->set(204, _isr204, selector);
    idt->set(205, _isr205, selector);
    idt->set(206, _isr206, selector);
    idt->set(207, _isr207, selector);
    idt->set(208, _isr208, selector);
    idt->set(209, _isr209, selector);
    idt->set(210, _isr210, selector);
    idt->set(211, _isr211, selector);
    idt->set(212, _isr212, selector);
    idt->set(213, _isr213, selector);
    idt->set(214, _isr214, selector);
    idt->set(215, _isr215, selector);
    idt->set(216, _isr216, selector);
    idt->set(217, _isr217, selector);
    idt->set(218, _isr218, selector);
    idt->set(219, _isr219, selector);
    idt->set(220, _isr220, selector);
    idt->set(221, _isr221, selector);
    idt->set(222, _isr222, selector);
    idt->set(223, _isr223, selector);
    idt->set(224, _isr224, selector);
    idt->set(225, _isr225, selector);
    idt->set(226, _isr226, selector);
    idt->set(227, _isr227, selector);
    idt->set(228, _isr228, selector);
    idt->set(229, _isr229, selector);
    idt->set(230, _isr230, selector);
    idt->set(231, _isr231, selector);
    idt->set(232, _isr232, selector);
    idt->set(233, _isr233, selector);
    idt->set(234, _isr234, selector);
    idt->set(235, _isr235, selector);
    idt->set(236, _isr236, selector);
    idt->set(237, _isr237, selector);
    idt->set(238, _isr238, selector);
    idt->set(239, _isr239, selector);
    idt->set(240, _isr240, selector);
    idt->set(241, _isr241, selector);
    idt->set(242, _isr242, selector);
    idt->set(243, _isr243, selector);
    idt->set(244, _isr244, selector);
    idt->set(245, _isr245, selector);
    idt->set(246, _isr246, selector);
    idt->set(247, _isr247, selector);
    idt->set(248, _isr248, selector);
    idt->set(249, _isr249, selector);
    idt->set(250, _isr250, selector);
    idt->set(251, _isr251, selector);
    idt->set(252, _isr252, selector);
    idt->set(253, _isr253, selector);
    idt->set(254, _isr254, selector);
    idt->set(255, _isr255, selector);
}
