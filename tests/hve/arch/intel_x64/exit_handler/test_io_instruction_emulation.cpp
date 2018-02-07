//
// Bareflank Extended APIs
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

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

#include "../../../../../include/support/arch/intel_x64/test_support.h"

namespace intel = intel_x64;
namespace vmcs = intel_x64::vmcs;
namespace io_qual = vmcs::exit_qualification::io_instruction;
namespace reason = vmcs::exit_reason::basic_exit_reason;
namespace proc_ctls = vmcs::primary_processor_based_vm_execution_controls;


TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: exit")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << io_qual::port_number::from;

    CHECK_NOTHROW(ehlr->dispatch());
    CHECK(ehlr->m_io_access_log[42] == 1);
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: log io access enabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << io_qual::port_number::from;

    g_vmcs[proc_ctls::addr] = 0xFFFFFFFFFFFFFFFF;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 1);
    CHECK(proc_ctls::use_io_bitmaps::is_disabled());

    g_vmcs[vmcs::exit_reason::addr] = reason::monitor_trap_flag;
    ehlr->dispatch();
    CHECK(proc_ctls::use_io_bitmaps::is_enabled());
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: log io access disabled")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(false);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << io_qual::port_number::from;

    g_vmcs[proc_ctls::addr] = 0xFFFFFFFFFFFFFFFF;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 0);
    CHECK(proc_ctls::use_io_bitmaps::is_disabled());

    g_vmcs[vmcs::exit_reason::addr] = reason::monitor_trap_flag;
    ehlr->dispatch();
    CHECK(proc_ctls::use_io_bitmaps::is_enabled());
}

TEST_CASE("exit_handler_intel_x64_eapis_io_instruction_emulation: clear io access log")
{
    MockRepository mocks;
    auto vmcs = setup_vmcs(mocks, reason::io_instruction);
    auto ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << io_qual::port_number::from;

    ehlr->dispatch();
    CHECK(ehlr->m_io_access_log[42] == 1);
    ehlr->clear_io_access_log();
    CHECK(ehlr->m_io_access_log[42] == 0);
}

#endif
