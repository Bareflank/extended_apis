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

#include <bitmanip.h>
#include <vmcs/ept_entry_intel_x64.h>

#include <intrinsics/x64.h>
using namespace x64;

ept_entry_intel_x64::ept_entry_intel_x64(gsl::not_null<pointer> pte) noexcept :
    m_epte(pte.get())
{ }

bool
ept_entry_intel_x64::read_access() const noexcept
{ return is_bit_set(*m_epte, 0); }

void
ept_entry_intel_x64::set_read_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 0) : clear_bit(*m_epte, 0); }

bool
ept_entry_intel_x64::write_access() const noexcept
{ return is_bit_set(*m_epte, 1); }

void
ept_entry_intel_x64::set_write_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 1) : clear_bit(*m_epte, 1); }

bool
ept_entry_intel_x64::execute_access() const noexcept
{ return is_bit_set(*m_epte, 2); }

void
ept_entry_intel_x64::set_execute_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 2) : clear_bit(*m_epte, 2); }

ept_entry_intel_x64::memory_type_type
ept_entry_intel_x64::memory_type() const noexcept
{ return get_bits(*m_epte, 0x0000000000000038UL) >> 3; }

void
ept_entry_intel_x64::set_memory_type(memory_type_type val) noexcept
{ *m_epte = set_bits(*m_epte, 0x0000000000000038UL, val << 3); }

bool
ept_entry_intel_x64::ignore_pat() const noexcept
{ return is_bit_set(*m_epte, 6); }

void
ept_entry_intel_x64::set_ignore_pat(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 6) : clear_bit(*m_epte, 6); }

bool
ept_entry_intel_x64::entry_type() const noexcept
{ return is_bit_set(*m_epte, 7); }

void
ept_entry_intel_x64::set_entry_type(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 7) : clear_bit(*m_epte, 7); }

bool
ept_entry_intel_x64::accessed() const noexcept
{ return is_bit_set(*m_epte, 8); }

void
ept_entry_intel_x64::set_accessed(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 8) : clear_bit(*m_epte, 8); }

bool
ept_entry_intel_x64::dirty() const noexcept
{ return is_bit_set(*m_epte, 9); }

void
ept_entry_intel_x64::set_dirty(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 9) : clear_bit(*m_epte, 9); }

bool
ept_entry_intel_x64::execute_access_user() const noexcept
{ return is_bit_set(*m_epte, 10); }

void
ept_entry_intel_x64::set_execute_access_user(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 10) : clear_bit(*m_epte, 10); }

ept_entry_intel_x64::integer_pointer
ept_entry_intel_x64::phys_addr() const noexcept
{ return get_bits(*m_epte, 0x0000FFFFFFFFF000UL); }

void
ept_entry_intel_x64::set_phys_addr(integer_pointer addr) noexcept
{ *m_epte = set_bits(*m_epte, 0x0000FFFFFFFFF000UL, addr); }

bool
ept_entry_intel_x64::suppress_ve() const noexcept
{ return is_bit_set(*m_epte, 63); }

void
ept_entry_intel_x64::set_suppress_ve(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 63) : clear_bit(*m_epte, 63); }

void
ept_entry_intel_x64::trap_on_access() noexcept
{
    this->set_read_access(false);
    this->set_write_access(false);
    this->set_execute_access(false);
}

void
ept_entry_intel_x64::pass_through_access() noexcept
{
    this->set_read_access(true);
    this->set_write_access(true);
    this->set_execute_access(true);
}

void
ept_entry_intel_x64::clear() noexcept
{ *m_epte = 0; }
