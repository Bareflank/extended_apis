#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
