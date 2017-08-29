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
# Colors
# ------------------------------------------------------------------------------

CB='\033[1;35m'
CC='\033[1;36m'
CE='\033[0m'

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
        if [[ $2 == "true" ]]; then
            echo -e "$CC""core:$CB #$core$CE"
            ARGS="--cpuid $core string json $1" make vmcall
            echo -e ""
        else
            ARGS="--cpuid $core string json $1" make vmcall > /dev/null
        fi
    done
}

# ------------------------------------------------------------------------------
# Init
# ------------------------------------------------------------------------------

run_on_all_cores "'{\"command\":\"enable_io_bitmaps\", \"enabled\": true}'"
run_on_all_cores "'{\"command\":\"clear_io_access_log\"}'"
run_on_all_cores "'{\"command\":\"log_io_access\", \"enabled\": true}'"
run_on_all_cores "'{\"command\":\"blacklist_io_access\", \"ports\": []}'"

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

header "without hypervisor"
time lspci > /dev/null
footer

header "with hypervisor"
run_on_all_cores "'{\"command\":\"whitelist_io_access\", \"ports\": []}'"
time lspci > /dev/null
footer

header "io access log"
footer
run_on_all_cores "'{\"command\":\"io_access_log\"}'" "true"

# ------------------------------------------------------------------------------
# Fini
# ------------------------------------------------------------------------------

run_on_all_cores "'{\"command\":\"blacklist_io_access\", \"ports\": []}'"
run_on_all_cores "'{\"command\":\"log_io_access\", \"enabled\": false}'"
run_on_all_cores "'{\"command\":\"clear_io_access_log\"}'"
run_on_all_cores "'{\"command\":\"enable_io_bitmaps\", \"enabled\": false}'"
