#!/bin/bash -e
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

# ------------------------------------------------------------------------------
# Environment
# ------------------------------------------------------------------------------

NUM_CORES=$(grep -c ^processor /proc/cpuinfo)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

header() {
    echo "----------------------------------------"
    echo $1
}

footer() {
    echo ""
}

run_on_all_cores() {
    for (( core=0; core<NUM_CORES; core++ ))
    do
        ARGS="--cpuid $core string json $1" make vmcall > /dev/null
    done
}

# ------------------------------------------------------------------------------
# Init
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

header "without vpid"
run_on_all_cores "'{\"command\":\"enable_vpid\", \"enabled\": false}'"
time lspci > /dev/null
footer

header "with vpid"
run_on_all_cores "'{\"command\":\"enable_vpid\", \"enabled\": true}'"
time lspci > /dev/null
footer

# ------------------------------------------------------------------------------
# Fini
# ------------------------------------------------------------------------------

run_on_all_cores "'{\"command\":\"enable_vpid\", \"enabled\": false}'"
