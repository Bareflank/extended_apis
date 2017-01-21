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

#include <test.h>

#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis.h>
#include <exit_handler/exit_handler_intel_x64_eapis_vmcall_interface.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

static std::map<intel_x64::msrs::field_type, intel_x64::msrs::value_type> g_msrs;
static std::map<intel_x64::vmcs::field_type, intel_x64::vmcs::value_type> g_vmcs;

uintptr_t g_rip = 0;
state_save_intel_x64 g_state_save{};
auto g_monitor_trap_callback_called = false;

bool g_enable_vpid = false;
exit_handler_intel_x64_eapis::port_type g_port = 0;

extern bool g_deny_all;
extern bool g_log_denials;

extern "C" bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs[field];
    return true;
}

extern "C"  bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs[field] = val;
    return true;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__stop(void) noexcept
{ }

extern "C" bool
__invept(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return true; }

extern "C" bool
__invvpid(uint64_t type, void *ptr) noexcept
{ (void) type; (void) ptr; return true; }

class exit_handler_ut : public exit_handler_intel_x64_eapis
{
public:
    void monitor_trap_callback()
    { g_monitor_trap_callback_called = true; }
};

auto
setup_vmcs(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = mocks.Mock<vmcs_intel_x64_eapis>();

    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::launch);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::resume);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::promote);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::load);
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::clear);

    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::enable_vpid).Do([&] { g_enable_vpid = true; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::disable_vpid).Do([&] { g_enable_vpid = false; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_io_access).Do([&](auto port) { g_port = port; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::trap_on_all_io_accesses).Do([&]() { g_port = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_io_access).Do([&](auto port) { g_port = port; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::pass_through_all_io_accesses).Do([&]() { g_port = 42; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::whitelist_io_access).Do([&](auto ports) { g_port = ports[0]; });
    mocks.OnCall(vmcs, vmcs_intel_x64_eapis::blacklist_io_access).Do([&](auto ports) { g_port = ports[0]; });

    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    g_vmcs[vmcs::exit_reason::addr] = reason;
    g_vmcs[vmcs::exit_qualification::addr] = 0;
    g_vmcs[vmcs::vm_exit_instruction_length::addr] = 8;
    g_vmcs[vmcs::vm_exit_instruction_information::addr] = 0;

    return vmcs;
}

auto
setup_ehlr(gsl::not_null<vmcs_intel_x64_eapis *> vmcs)
{
    auto &&ehlr = std::make_unique<exit_handler_ut>();
    ehlr->set_vmcs(vmcs);
    ehlr->set_state_save(&g_state_save);

    g_rip = ehlr->m_state_save->rip + g_vmcs[vmcs::vm_exit_instruction_length::addr];
    return std::move(ehlr);
}

void
eapis_ut::test_resume()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { ehlr->resume(); });
    });
}

void
eapis_ut::test_resume_and_advance()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { ehlr->advance_and_resume(); });
        this->expect_true(ehlr->m_state_save->rip == g_rip);
    });
}

void
eapis_ut::test_handle_exit_invalid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { ehlr->dispatch(); });
    });
}

void
eapis_ut::test_handle_exit_monitor_trap_flag()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->register_monitor_trap(&exit_handler_ut::monitor_trap_callback);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { ehlr->dispatch(); });
    });
}

void
eapis_ut::test_handle_exit_io_instruction()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&] { ehlr->dispatch(); });
        this->expect_true(ehlr->m_io_access_log[42] == 1);
    });
}

void
eapis_ut::test_register_monitor_trap()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->register_monitor_trap(&exit_handler_ut::monitor_trap_callback);
    ehlr->dispatch();
    ehlr->clear_monitor_trap();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(g_monitor_trap_callback_called);
        this->expect_exception([&]{ ehlr->dispatch(); }, ""_ut_lee);
    });
}

void
eapis_ut::test_clear_monitor_trap_by_default()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::monitor_trap_flag);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->dispatch(); }, ""_ut_lee);
    });
}

void
eapis_ut::test_log_io_access_enabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vmcs[primary_processor_based_vm_execution_controls::addr] = 0xFFFFFFFFFFFFFFFF;

        ehlr->dispatch();
        this->expect_true(ehlr->m_io_access_log[42] == 1);
        this->expect_true(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled());

        g_vmcs[vmcs::exit_reason::addr] = exit_reason::basic_exit_reason::monitor_trap_flag;
        ehlr->dispatch();
        this->expect_true(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
    });
}

void
eapis_ut::test_log_io_access_disabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(false);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_vmcs[primary_processor_based_vm_execution_controls::addr] = 0xFFFFFFFFFFFFFFFF;

        ehlr->dispatch();
        this->expect_true(ehlr->m_io_access_log[42] == 0);
        this->expect_true(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_disabled());

        g_vmcs[vmcs::exit_reason::addr] = exit_reason::basic_exit_reason::monitor_trap_flag;
        ehlr->dispatch();
        this->expect_true(primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());
    });
}

void
eapis_ut::test_clear_io_access_log()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, exit_reason::basic_exit_reason::io_instruction);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr->log_io_access(true);
    g_vmcs[vmcs::exit_qualification::addr] = 42 << exit_qualification::io_instruction::port_number::from;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        ehlr->dispatch();
        this->expect_true(ehlr->m_io_access_log[42] == 1);
        ehlr->clear_io_access_log();
        this->expect_true(ehlr->m_io_access_log[42] == 0);
    });
}

void
eapis_ut::test_handle_vmcall_overrun_denials_buffer()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        for (auto i = 0; i < DENIAL_LOG_SIZE + 10; i++)
            this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });

        this->expect_true(ehlr->m_denials.size() == DENIAL_LOG_SIZE);
    });
}

void
eapis_ut::test_handle_vmcall_registers_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = 0xDEADBEEF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = 0xDEADBEEF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_true(g_port == 0);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_trap_on_all_io_accesses_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__trap_on_all_io_accesses;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_true(g_port == 0);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_io_access;
    regs.r04 = 42;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_true(g_port == 0);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_io_instruction_pass_through_all_io_accesses_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__io_instruction;
    regs.r03 = eapis_fun__pass_through_all_io_accesses;

    g_port = 0;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_true(g_port == 0);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_json_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "unknown_api"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ree);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_trap_on_io_access_missing_port()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "trap_on_io_access"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_trap_on_io_access_invalid_port()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "trap_on_io_access"}, {"port", "bad port"}};
    json ijson2 = {{"set", "trap_on_io_access"}, {"port_hex", 10}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); }, ""_ut_ree);
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_trap_on_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_trap_on_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 2);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_trap_on_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "trap_on_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "trap_on_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);

        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_pass_through_io_access_missing_port()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "pass_through_io_access"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_pass_through_io_access_invalid_port()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "pass_through_io_access"}, {"port", "bad port"}};
    json ijson2 = {{"set", "pass_through_io_access"}, {"port_hex", 10}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); }, ""_ut_ree);
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_pass_through_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_pass_through_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 2);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_pass_through_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "pass_through_io_access"}, {"port", 42}};
    json ijson2 = {{"set", "pass_through_io_access"}, {"port_hex", "0x2A"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);

        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_whitelist_io_access_missing_ports()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "whitelist_io_access"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_whitelist_io_access_invalid_ports()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "whitelist_io_access"}, {"ports", "bad port"}};
    json ijson2 = {{"set", "whitelist_io_access"}, {"ports_hex", 10}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); }, ""_ut_ree);
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_whitelist_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_whitelist_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 2);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_whitelist_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "whitelist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "whitelist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);

        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_blacklist_io_access_missing_ports()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "blacklist_io_access"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_blacklist_io_access_invalid_ports()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "blacklist_io_access"}, {"ports", "bad port"}};
    json ijson2 = {{"set", "blacklist_io_access"}, {"ports_hex", 10}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); }, ""_ut_ree);
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_blacklist_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_blacklist_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 1);

        g_port = 0;
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(g_port == 42);
        this->expect_true(ehlr->m_denials.size() == 2);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_blacklist_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson1 = {{"set", "blacklist_io_access"}, {"ports", {42}}};
    json ijson2 = {{"set", "blacklist_io_access"}, {"ports_hex", {"0x2A"}}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson1, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);

        g_port = 0;
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson2, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_port == 0);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_log_io_access_missing_enabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "log_io_access"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_log_io_access_invalid_enabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "log_io_access"}, {"enabled", "not a bool"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_dme);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_log_io_access_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_log_io_access_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_log_io_access_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "log_io_access"}, {"enabled", false}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_clear_io_access_log_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_clear_io_access_log_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_clear_io_access_log_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_io_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_io_access_log_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"get", "io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "{\"0x2A\":42}");
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_io_access_log_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"get", "io_access_log"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "{\"0x2A\":42}");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_json_io_instruction_io_access_log_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"get", "io_access_log"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();
    ehlr->m_io_access_log[42] = 42;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "{\"0x2A\":42}");
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = 0xDEADBEEF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_enable_vpid_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_enable_vpid);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_enable_vpid_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_true(g_enable_vpid);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_enable_vpid_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__enable_vpid;

    g_enable_vpid = false;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_false(g_enable_vpid);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_disable_vpid_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_false(g_enable_vpid);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_disable_vpid_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_registers(regs); });
        this->expect_false(g_enable_vpid);
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_registers_vpid_disable_vpid_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    vmcall_registers_t regs = {};
    regs.r02 = eapis_cat__vpid;
    regs.r03 = eapis_fun__disable_vpid;

    g_enable_vpid = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_registers(regs); }, ""_ut_ree);
        this->expect_true(g_enable_vpid);
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_json_vpid_enable_vpid_missing_enabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_ore);
    });
}

void
eapis_ut::test_handle_vmcall_json_vpid_enable_vpid_invalid_enabled()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}, {"enabled", "not a bool"}};
    json ojson = {};

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); }, ""_ut_dme);
    });
}

void
eapis_ut::test_handle_vmcall_json_vpid_enable_vpid_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_false(g_enable_vpid);
    });
}

void
eapis_ut::test_handle_vmcall_json_vpid_enable_vpid_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = false;
    g_log_denials = true;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
        this->expect_false(g_enable_vpid);
    });
}

void
eapis_ut::test_handle_vmcall_json_vpid_enable_vpid_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"set", "vpid"}, {"enabled", false}};
    json ojson = {};

    g_enable_vpid = true;
    g_deny_all = true;
    g_log_denials = false;

    ehlr->clear_denials();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(g_enable_vpid);
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_clear_denials_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_clear_denials_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"success\"]");
        this->expect_true(ehlr->m_denials.empty());
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_clear_denials_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"run", "clear_denials"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"success\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_policy_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "policy"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_policy_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "policy"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_policy_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "policy"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_denials_allowed()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = false;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ojson.dump() == "[\"fake denial\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_denials_logged()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "denials"}};
    json ojson = {};

    g_deny_all = false;
    g_log_denials = true;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); });
        this->expect_true(ehlr->m_denials.size() == 2);
    });
}

void
eapis_ut::test_handle_vmcall_json_verifiers_dump_denials_denied()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs(mocks, 0x0);
    auto &&ehlr = setup_ehlr(vmcs);

    json ijson = {{"dump", "denials"}};
    json ojson = {};

    g_deny_all = true;
    g_log_denials = false;
    ehlr->m_denials.push_back("fake denial");

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_exception([&]{ ehlr->handle_vmcall_data_string_json(ijson, ojson); },  ""_ut_ree);
        this->expect_true(ojson.dump() != "[\"fake denial\"]");
        this->expect_true(ehlr->m_denials.size() == 1);
    });
}
