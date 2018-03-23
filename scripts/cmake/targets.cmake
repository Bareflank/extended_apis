#
# Bareflank Hypervisor
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

if(NOT WIN32 AND NOT CYGWIN)
    set(SUDO sudo)
else()
    set(SUDO "")
endif()

# ------------------------------------------------------------------------------
# Integration Driver
# ------------------------------------------------------------------------------

if(NOT WIN32 AND ENABLE_BUILD_INTEGRATION)
    add_custom_target_category("Bareflank Test Driver")

    set(SOURCE_UTIL_DIR ${CMAKE_CURRENT_LIST_DIR}/../util)
    set(SOURCE_BFDRIVER_DIR ${CMAKE_CURRENT_LIST_DIR}/../../bfdriver)

    add_custom_target(bftest_build
        COMMAND ${SOURCE_UTIL_DIR}/driver_build.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET bftest_build
        COMMENT "Build the Bareflank test driver"
    )

    add_custom_target(bftest_clean
        COMMAND ${SOURCE_UTIL_DIR}/driver_clean.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET bftest_clean
        COMMENT "Clean the Bareflank test driver"
    )

    add_custom_target(bftest_load
        COMMAND ${SOURCE_UTIL_DIR}/driver_load.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET bftest_load
        COMMENT "Load the Bareflank test driver"
    )

    add_custom_target(bftest_unload
        COMMAND ${SOURCE_UTIL_DIR}/driver_unload.sh ${SOURCE_BFDRIVER_DIR}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET bftest_unload
        COMMENT "Unload the Bareflank test driver"
    )

    add_custom_target(
        bftest_quick
        COMMAND ${CMAKE_COMMAND} --build . --target bftest_unload
        COMMAND ${CMAKE_COMMAND} --build . --target bftest_clean
        COMMAND ${CMAKE_COMMAND} --build . --target bftest_build
        COMMAND ${CMAKE_COMMAND} --build . --target bftest_load
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET bftest_quick
        COMMENT "Unload, clean, build, and load the Bareflank test driver"
    )
endif()
