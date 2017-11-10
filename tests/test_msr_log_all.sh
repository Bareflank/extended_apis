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
            bfm vmcall string json "$1"
            echo -e ""
        else
            bfm vmcall string json "$1" > /dev/null
        fi
    done
}

# ------------------------------------------------------------------------------
# Init
# ------------------------------------------------------------------------------

run_on_all_cores "{\"command\":\"enable_msr_bitmap\", \"enabled\": true}"
run_on_all_cores "{\"command\":\"clear_rdmsr_access_log\"}"
run_on_all_cores "{\"command\":\"clear_wrmsr_access_log\"}"
run_on_all_cores "{\"command\":\"log_rdmsr_access\", \"enabled\": true}"
run_on_all_cores "{\"command\":\"log_wrmsr_access\", \"enabled\": true}"
run_on_all_cores "{\"command\":\"blacklist_rdmsr_access\", \"msrs\": []}"
run_on_all_cores "{\"command\":\"blacklist_wrmsr_access\", \"msrs\": []}"

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

run_on_all_cores "{\"command\":\"whitelist_rdmsr_access\", \"msrs\": []}"
run_on_all_cores "{\"command\":\"whitelist_wrmsr_access\", \"msrs\": []}"
sleep 1
run_on_all_cores "{\"command\":\"blacklist_rdmsr_access\", \"msrs\": []}"
run_on_all_cores "{\"command\":\"blacklist_wrmsr_access\", \"msrs\": []}"

header "rdmsr access log"
footer
run_on_all_cores "{\"command\":\"rdmsr_access_log\"}" "true"

header "wrmsr access log"
footer
run_on_all_cores "{\"command\":\"wrmsr_access_log\"}" "true"

# ------------------------------------------------------------------------------
# Fini
# ------------------------------------------------------------------------------

run_on_all_cores "{\"command\":\"blacklist_rdmsr_access\", \"msrs\": []}"
run_on_all_cores "{\"command\":\"blacklist_wrmsr_access\", \"msrs\": []}"
run_on_all_cores "{\"command\":\"log_rdmsr_access\", \"enabled\": false}"
run_on_all_cores "{\"command\":\"log_wrmsr_access\", \"enabled\": false}"
run_on_all_cores "{\"command\":\"clear_rdmsr_access_log\"}"
run_on_all_cores "{\"command\":\"clear_wrmsr_access_log\"}"
run_on_all_cores "{\"command\":\"enable_msr_bitmap\", \"enabled\": false}"
