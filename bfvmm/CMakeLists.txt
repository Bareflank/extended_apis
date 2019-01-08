#
# Bareflank Extended APIs
# Copyright (C) 2018 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.6)
project(eapis C CXX)

# -----------------------------------------------------------------------------
# Generator expressions
# -----------------------------------------------------------------------------

set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)

# -----------------------------------------------------------------------------
# Project
# -----------------------------------------------------------------------------

init_project(eapis INTERFACE)

# -----------------------------------------------------------------------------
# HVE
# -----------------------------------------------------------------------------

add_library(eapis_hve)
target_link_libraries(eapis_hve PUBLIC vmm::bfvmm)
target_include_directories(eapis_hve PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)
target_sources(eapis_hve PRIVATE
    $<${X64}:src/hve/arch/intel_x64/vmexit/control_register.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/cpuid.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/ept_misconfiguration.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/ept_violation.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/external_interrupt.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/init_signal.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/interrupt_window.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/io_instruction.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/monitor_trap.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/rdmsr.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/sipi_signal.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/preemption_timer.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/wrmsr.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/xsetbv.cpp>
    $<${X64}:src/hve/arch/intel_x64/cpuid.cpp>
    $<${X64}:src/hve/arch/intel_x64/ept.cpp>
    $<${X64}:src/hve/arch/intel_x64/interrupt_queue.cpp>
    $<${X64}:src/hve/arch/intel_x64/microcode.cpp>
    $<${X64}:src/hve/arch/intel_x64/mtrrs.cpp>
    $<${X64}:src/hve/arch/intel_x64/vcpu.cpp>
    $<${X64}:src/hve/arch/intel_x64/vpid.cpp>
    $<${X64}:src/hve/arch/x64/unmapper.cpp>
)

# -----------------------------------------------------------------------------
# VMM
# -----------------------------------------------------------------------------

add_executable(eapis_vmm)
target_sources(eapis_vmm PRIVATE src/main/arch/intel_x64/vcpu_factory.cpp)
target_link_libraries(eapis_vmm PRIVATE eapis_hve)
target_link_libraries(eapis INTERFACE eapis_hve)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

install(TARGETS eapis_hve DESTINATION lib EXPORT eapis-vmm-targets)
install(TARGETS eapis_vmm DESTINATION bin EXPORT eapis-vmm-targets)
install(DIRECTORY include/ DESTINATION include/eapis)

fini_project()
