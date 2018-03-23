/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>

/* -------------------------------------------------------------------------- */
/* Minimal vmcall interface                                                   */
/* -------------------------------------------------------------------------- */

struct vmcall_args {
    uintptr_t rax;
    uintptr_t rdx;
    uintptr_t rcx;
    uintptr_t rbx;
};

static inline void
vmcall(struct vmcall_args *arg)
{
    asm volatile(
        "movq %4, %%rax \n\t"
        "movq %5, %%rbx \n\t"
        "movq %6, %%rcx \n\t"
        "movq %7, %%rdx \n\t"
        "vmcall         \n\t"
        "movq %%rax, %0 \n\t"
        "movq %%rbx, %1 \n\t"
        "movq %%rcx, %2 \n\t"
        "movq %%rdx, %3 \n\t"
        : "=m"(arg[0]), "=m"(arg[1]), "=m"(arg[2]), "=m"(arg[3])
        : "a"(arg[0]), "b"(arg[1]), "c"(arg[2]), "d"(arg[3])
    );
}

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
bftest_init(void)
{
    BFDEBUG("bftest_init succeeded\n");
    return 0;
}

void
bftest_exit(void)
{
    BFDEBUG("bftest_exit succeeded\n");
    return;
}

module_init(bftest_init);
module_exit(bftest_exit);

MODULE_LICENSE("GPL");
