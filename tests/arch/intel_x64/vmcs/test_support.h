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

#ifndef TEST_SUPPORT_H
#define TEST_SUPPORT_H

#include <memory>
#include <hippomocks.h>

#include <bfgsl.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <memory_manager/memory_manager_x64.h>

memory_manager_x64 *setup_mm(MockRepository &mocks);
std::unique_ptr<vmcs_intel_x64_eapis> setup_vmcs(MockRepository &mocks);

#endif
