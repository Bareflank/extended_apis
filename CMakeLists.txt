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

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)

# ------------------------------------------------------------------------------
# Project File
# ------------------------------------------------------------------------------

add_project_include(${EAPIS_SOURCE_CMAKE_DIR}/macros.cmake)

# ------------------------------------------------------------------------------
# VMM Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    add_subproject(
        eapis_bfvmm vmm
        DEPENDS bfvmm
        DEPENDS bfintrinsics
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    add_subproject(
        eapis_bfvmm_main vmm
        DEPENDS eapis_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )

    add_subproject(
        eapis_integration vmm
        DEPENDS eapis_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/
    )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

# if(ENABLE_BUILD_TEST)
#     add_subproject(
#         eapis_bfvmm test
#         DEPENDS bfvmm
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/tests/
#     )
# endif()

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

userspace_extension(
    ack
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfack
    DEPENDS bfintrinsics
)

# ------------------------------------------------------------------------------
# Custom Target
# ------------------------------------------------------------------------------

add_custom_target_category("EAPI Commands")

add_custom_target(ack
    COMMAND ${USERSPACE_PREFIX_PATH}/bin/ack
    USES_TERMINAL
)

add_custom_target_info(
    TARGET ack
    COMMENT "Ack the hypervisor"
)
