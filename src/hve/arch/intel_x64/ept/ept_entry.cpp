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

#include <util/bitmanip.h>
#include "../../../../../include/hve/arch/intel_x64/ept/ept_entry.h"

#include <arch/x64/misc.h>

namespace intel = eapis::intel_x64;

intel::ept_entry::ept_entry(gsl::not_null<pointer> pte) noexcept :
    m_epte(pte.get())
{ }

intel::ept_entry::pointer
intel::ept_entry::epte() const noexcept
{ return m_epte; }

void
intel::ept_entry::set_epte(pointer val) noexcept
{ m_epte = val; }

intel::ept_entry::epte_value
intel::ept_entry::epte_val() const noexcept
{ return *m_epte; }

void
intel::ept_entry::set_epte_val(epte_value val) noexcept
{ *m_epte = val; }

bool
intel::ept_entry::read_access() const noexcept
{ return is_bit_set(*m_epte, 0); }

void
intel::ept_entry::set_read_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 0) : clear_bit(*m_epte, 0); }

bool
intel::ept_entry::write_access() const noexcept
{ return is_bit_set(*m_epte, 1); }

void
intel::ept_entry::set_write_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 1) : clear_bit(*m_epte, 1); }

bool
intel::ept_entry::execute_access() const noexcept
{ return is_bit_set(*m_epte, 2); }

void
intel::ept_entry::set_execute_access(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 2) : clear_bit(*m_epte, 2); }

intel::ept_entry::memory_type_type
intel::ept_entry::memory_type() const noexcept
{ return get_bits(*m_epte, 0x0000000000000038ULL) >> 3; }

void
intel::ept_entry::set_memory_type(memory_type_type val) noexcept
{ *m_epte = set_bits(*m_epte, 0x0000000000000038ULL, val << 3); }

bool
intel::ept_entry::ignore_pat() const noexcept
{ return is_bit_set(*m_epte, 6); }

void
intel::ept_entry::set_ignore_pat(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 6) : clear_bit(*m_epte, 6); }

bool
intel::ept_entry::entry_type() const noexcept
{ return is_bit_set(*m_epte, 7); }

void
intel::ept_entry::set_entry_type(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 7) : clear_bit(*m_epte, 7); }

bool
intel::ept_entry::accessed() const noexcept
{ return is_bit_set(*m_epte, 8); }

void
intel::ept_entry::set_accessed(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 8) : clear_bit(*m_epte, 8); }

bool
intel::ept_entry::dirty() const noexcept
{ return is_bit_set(*m_epte, 9); }

void
intel::ept_entry::set_dirty(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 9) : clear_bit(*m_epte, 9); }

bool
intel::ept_entry::execute_access_user() const noexcept
{ return is_bit_set(*m_epte, 10); }

void
intel::ept_entry::set_execute_access_user(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 10) : clear_bit(*m_epte, 10); }

intel::ept_entry::integer_pointer
intel::ept_entry::phys_addr() const noexcept
{ return get_bits(*m_epte, 0x0000FFFFFFFFF000ULL); }

void
intel::ept_entry::set_phys_addr(integer_pointer addr) noexcept
{ *m_epte = set_bits(*m_epte, 0x0000FFFFFFFFF000ULL, addr); }

bool
intel::ept_entry::suppress_ve() const noexcept
{ return is_bit_set(*m_epte, 63); }

void
intel::ept_entry::set_suppress_ve(bool enabled) noexcept
{ *m_epte = enabled ? set_bit(*m_epte, 63) : clear_bit(*m_epte, 63); }

void
intel::ept_entry::trap_on_access() noexcept
{
    this->set_read_access(false);
    this->set_write_access(false);
    this->set_execute_access(false);
}

void
intel::ept_entry::pass_through_access() noexcept
{
    this->set_read_access(true);
    this->set_write_access(true);
    this->set_execute_access(true);
}

void
intel::ept_entry::clear() noexcept
{ *m_epte = 0; }
