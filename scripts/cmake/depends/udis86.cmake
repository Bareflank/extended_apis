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
    message(STATUS "Including dependency: udis86")
    find_program(PYTHON_BIN python2 REQUIRED)

    download_dependency(
        udis86
        URL         ${UDIS86_URL}
        URL_MD5     ${UDIS86_URL_MD5}
    )
endif()

if(ENABLE_BUILD_VMM)
    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND UDIS86_CONFIGURE_FLAGS
        --prefix=${VMM_PREFIX_PATH}
        --with-python=${PYTHON_BIN}
    )

    add_dependency(
        udis86 vmm
        CONFIGURE_COMMAND    ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 ./autogen.sh
                  COMMAND ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 ./configure "${UDIS86_CONFIGURE_FLAGS}"
        BUILD_COMMAND     ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 make
        INSTALL_COMMAND   ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 make install
        DEPENDS newlib_${VMM_PREFIX}
    )

endif()

if(ENABLE_BUILD_TEST)
    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND UDIS86_CONFIGURE_FLAGS
        --prefix=${VMM_PREFIX_PATH}
        --with-python=${PYTHON_BIN}
    )

    add_dependency(
        udis86 test
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 ./autogen.sh
                  COMMAND ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 ./configure "${UDIS86_CONFIGURE_FLAGS}"
        BUILD_COMMAND     ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 make
        INSTALL_COMMAND   ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/udis86 make install
    )
endif()
