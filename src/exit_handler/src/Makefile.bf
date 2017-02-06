#
# Bareflank Extended APIs
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

################################################################################
# Target Information
################################################################################

TARGET_NAME:=exit_handler_intel_x64_eapis
TARGET_TYPE:=lib

ifeq ($(shell uname -s), Linux)
    TARGET_COMPILER:=both
else
    TARGET_COMPILER:=cross
endif

################################################################################
# Compiler Flags
################################################################################

NATIVE_CCFLAGS+=
NATIVE_CXXFLAGS+=
NATIVE_ASMFLAGS+=
NATIVE_LDFLAGS+=
NATIVE_ARFLAGS+=
NATIVE_DEFINES+=SHOW_VMCALLS

CROSS_CCFLAGS+=
CROSS_CXXFLAGS+=
CROSS_ASMFLAGS+=
CROSS_LDFLAGS+=
CROSS_ARFLAGS+=
CROSS_DEFINES+=

################################################################################
# Output
################################################################################

CROSS_OBJDIR+=%BUILD_REL%/.build
CROSS_OUTDIR+=%BUILD_REL%/../bin

NATIVE_OBJDIR+=%BUILD_REL%/.build
NATIVE_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

SOURCES+=exit_handler_intel_x64_eapis.cpp
SOURCES+=exit_handler_intel_x64_eapis_verifiers.cpp
SOURCES+=exit_handler_intel_x64_eapis_verifiers_vmcall.cpp
SOURCES+=exit_handler_intel_x64_eapis_io_instruction_emulation.cpp
SOURCES+=exit_handler_intel_x64_eapis_io_instruction_vmcall.cpp
SOURCES+=exit_handler_intel_x64_eapis_monitor_trap_emulation.cpp
SOURCES+=exit_handler_intel_x64_eapis_vpid_vmcall.cpp
SOURCES+=exit_handler_intel_x64_eapis_msr_vmcall.cpp
SOURCES+=exit_handler_intel_x64_eapis_rdmsr_emulation.cpp
SOURCES+=exit_handler_intel_x64_eapis_rdmsr_vmcall.cpp
SOURCES+=exit_handler_intel_x64_eapis_wrmsr_emulation.cpp
SOURCES+=exit_handler_intel_x64_eapis_wrmsr_vmcall.cpp

INCLUDE_PATHS+=../../../include
INCLUDE_PATHS+=%HYPER_ABS%/include/
INCLUDE_PATHS+=%HYPER_ABS%/bfvmm/include/

LIBS+=

LIBRARY_PATHS+=

################################################################################
# Environment Specific
################################################################################

VMM_SOURCES+=
VMM_INCLUDE_PATHS+=
VMM_LIBS+=
VMM_LIBRARY_PATHS+=

WINDOWS_SOURCES+=
WINDOWS_INCLUDE_PATHS+=
WINDOWS_LIBS+=
WINDOWS_LIBRARY_PATHS+=

LINUX_SOURCES+=
LINUX_INCLUDE_PATHS+=
LINUX_LIBS+=
LINUX_LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
