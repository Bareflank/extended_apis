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

run_on_all_cores "{\"command\":\"clear_cpuid_access_log\"}"
run_on_all_cores "{\"command\":\"log_cpuid_access\", \"enabled\": true}"
run_on_all_cores "{\"command\":\"reset_cpuid_all\"}"

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------


header "emulate cpuid"
run_on_all_cores "{\"command\":\"emulate_cpuid\", \"leaf\": 0, \"subleaf\": 0,
                    \"eax\": \"00000000000000000000000000001000\",
                    \"ebx\": \"00000000000000000000000000001000\",
                    \"ecx\": \"00000000000000000000000000001000\",
                    \"edx\": \"00000000000000000000000000001000\"}"
run_on_all_cores "{\"command\":\"emulate_cpuid\", \"leaf\": 1, \"subleaf\": 0,
                    \"eax\": \"-01-01-01-01-01-01-01-01-01-01-0\",
                    \"ebx\": \"01-01-01-01-01-01-01-01-01-01-01\",
                    \"ecx\": \"1-01-01-01-01-01-01-01-01-01-01-\",
                    \"edx\": \"----00001111----00001111----0000\"}"
run_on_all_cores "{\"command\":\"emulate_cpuid\", \"leaf\": 2, \"subleaf\": 0,
                    \"eax\": \"--------------------------------\",
                    \"ebx\": \"--------------------------------\",
                    \"ecx\": \"--------------------------------\",
                    \"edx\": \"--------------------------------\"}"
footer

header "cpuid emulations log"
run_on_all_cores "{\"command\":\"dump_cpuid_emulations_log\"}" "true"
footer

header "reset cpuid leaf"
run_on_all_cores "{\"command\":\"reset_cpuid_leaf\", \"leaf\": 1, \"subleaf\": 0}"
footer

header "cpuid emulations log"
run_on_all_cores "{\"command\":\"dump_cpuid_emulations_log\"}" "true"
footer

header "reset cpuid all"
run_on_all_cores "{\"command\":\"reset_cpuid_all\"}"
footer

header "cpuid emulations log"
run_on_all_cores "{\"command\":\"dump_cpuid_emulations_log\"}" "true"
footer

header "cpuid access log"
run_on_all_cores "{\"command\": \"cpuid_access_log\"}" "true"
footer

header "invalid emulate cpuid (expect fail)"
set +e
run_on_all_cores "{\"command\":\"emulate_cpuid\", \"leaf\": 3, \"subleaf\": 0,
                    \"eax\": \"DEADBEEFDEADBEEFDEADBEEFDEADBEEF\",
                    \"ebx\": \"----00001111----00001111----00001111\",
                    \"ecx\": \"----00001111----00001111\",
                    \"edx\": \"--------------------------------\"}"
set -e
footer

header "cpuid emulations log"
run_on_all_cores "{\"command\":\"dump_cpuid_emulations_log\"}" "true"
footer

# ------------------------------------------------------------------------------
# Fini
# ------------------------------------------------------------------------------

run_on_all_cores "{\"command\":\"reset_cpuid_all\"}"
run_on_all_cores "{\"command\":\"log_cpuid_access\", \"enabled\": false}"
run_on_all_cores "{\"command\":\"clear_cpuid_access_log\"}"
