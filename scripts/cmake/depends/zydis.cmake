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

if(ENABLE_BUILD_VMM OR ENABLE_BUILD_TEST)
    message(STATUS "Including dependency: zydis")

    download_dependency(
        zydis
        URL         ${ZYDIS_URL}
        URL_MD5     ${ZYDIS_URL_MD5}
    )
endif()

if(ENABLE_BUILD_VMM)
    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND ZYDIS_CONFIGURE_FLAGS
        -DZYDIS_BUILD_EXAMPLES=OFF
        -DZYDIS_BUILD_TOOLS=OFF
        -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
        -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} -DZYDIS_NO_LIBC"
        -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -DZYDIS_NO_LIBC"
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_PATH}
        -DCMAKE_C_COMPILER_WORKS=1
        -DCMAKE_CXX_COMPILER_WORKS=1
    )

    add_dependency(
        zydis vmm
        CMAKE_ARGS ${ZYDIS_CONFIGURE_FLAGS}
    )

endif()

if(ENABLE_BUILD_TEST)
    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND ZYDIS_CONFIGURE_FLAGS
        -DZYDIS_BUILD_EXAMPLES=OFF
        -DZYDIS_BUILD_TOOLS=OFF
        -DBUILD_SHARED_LIBS=${BUILD_SHARED_LIBS}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DCMAKE_TOOLCHAIN_FILE=${TEST_TOOLCHAIN_PATH}
        -DCMAKE_C_COMPILER_WORKS=1
        -DCMAKE_CXX_COMPILER_WORKS=1
    )

    add_dependency(
        zydis test
        CMAKE_ARGS ${ZYDIS_CONFIGURE_FLAGS}
    )
endif()
