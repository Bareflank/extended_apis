#!/bin/bash

set -e

reset="\e[0m"
bold="\e[1m"
red="\e[91m"
green="\e[92m"
yellow="\e[93m"
blue="\e[94m"
cyan="\e[96m"
white="\e[99m"

bold_red="\e[1;91m"
bold_green="\e[1;92m"
bold_yellow="\e[1;93m"
bold_blue="\e[1;94m"
bold_cyan="\e[1;96m"
bold_white="\e[1;99m"

#
# Global variables
#

case $LANG in
    en_US\.UTF-8)
        pass_mark='\u2713'
        fail_mark='\u2718'
        ;;
    *)
        pass_mark='*'
        fail_mark='x'
        ;;
esac

pass_mark="$bold_green$pass_mark$reset"
fail_mark="$bold_red$fail_mark$reset"

cpu_count=$(nproc)

option_fall_through=0
option_keep_dumps=0
option_help=0

while [[ $# -gt 0 ]]
do
    case "$1" in
        --fall-through)
            option_fall_through=1
            shift
            ;;
        --keep-dumps)
            option_keep_dumps=1
            shift
            ;;
        --help|-h)
            option_help=1
            shift
            ;;
        --)
            shift
            break
            ;;
        --*|-*)
            echo "unrecognized option: $1"
            exit 1
            ;;
        *)
            break
            ;;
    esac
done


if [[ $# -ne 3 ]] || [[ $option_help -ne 0 ]];
then
    echo "usage: $(basename $0) [options] <build-dir> <hypervisor-src> <eapis-debug-config>"
    echo
    echo "options:"
    echo "  --help | -h     Display this text"
    echo "  --fall-through  Continue running tests if one fails"
    echo "  --keep-dumps    Keep serial dumps from all tests"
    exit $(( ! option_help ))
fi

build_dir=$1
hyp_src=$2
config=$3
vmm_bin_dir=$build_dir/prefixes/x86_64-vmm-elf/bin
bfm=$build_dir/prefixes/x86_64-userspace-elf/bin/bfm

#
# Helpers
#

echo_milestone()
{
    echo -ne "$bold_green==>$reset $bold_white$1$reset"
}

echo_task()
{
    echo -ne "  $bold_blue->$reset $bold_white$1$reset"
}

echo_pass()
{
    echo -ne " -$bold_white pass $reset$pass_mark$reset"
}

echo_fail()
{
    echo -ne " -$bold_white fail $reset$fail_mark$reset"

    local reason=$1
    if [[ ! -z $reason ]];
    then
        echo ""
        echo -ne "  $bold_red-> reason: $reason$reset"
    fi
}

die_or_fall_through()
{
    if [[ $option_fall_through -eq 0 ]]
    then
        exit 1
    fi
}

#
# Common checks for all integration tests
#

check_test_all() {

    now_count=$(grep "now" serial.out | wc -l)
    not_count=$(grep "not" serial.out | wc -l)

    if [[ $now_count -ne $cpu_count ]];
    then
        echo_fail "observed $now_count host os demotions; expected $cpu_count"
        echo ""
        exit 1
    fi

    if [[ $not_count -ne $cpu_count ]];
    then
        echo_fail "observed $not_count host os promotions; expected $cpu_count"
        echo ""
        exit 1
    fi

    return 0
}

#
# Test-specific checks
#

check_monitor_trap()
{
    local mtr_count=$(grep "trapped" serial.out | wc -l)

    if [[ $mtr_count -ne $cpu_count ]];
    then
        echo_fail "observed $mtr_count monitor traps; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    return 0
}

check_vpid()
{
    local vpid_count=$(grep "vpid" serial.out | wc -l)

    if [[ $vpid_count -ne $cpu_count ]];
    then
        echo_fail "observed $vpid_count vpids; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    return 0
}

check_phys_pci()
{
    return 0
}

check_vic()
{
    local spurious_count=$(dmesg | grep -i "spurious" | wc -l)

    if [[ $spurious_count -ne $cpu_count ]];
    then
        echo_fail "observed $spurious_count spurious interrupts; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    return 0
}

check_msr()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local msr_count=$(grep "\- msr" serial.out | wc -l)
    local val_count=$(grep "\- val" serial.out | wc -l)

    if [[ $record_count -eq $msr_count && $msr_count -eq $val_count ]];
    then
        if [[ $record_count -gt 0 ]];
        then
            return 0
        else
            echo_fail "observed $record_count records; expected at least one"
            echo ""
            die_or_fall_through; return 0
        fi
    fi

    echo ""
    echo_fail "observed $record_count records; expected $record_count"
    echo_fail "observed $msr_count msrs; expected $record_count"
    echo_fail "observed $val_count vals; expected $record_count"
    echo ""
    die_or_fall_through; return 0
}

check_dr()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local val_count=$(grep "\- val" serial.out | wc -l)

    if [[ $record_count -eq $val_count ]];
    then
        if [[ $record_count -gt 0 ]];
        then
            return 0
        else
            echo_fail "observed $record_count records; expected at least one"
            echo ""
            die_or_fall_through; return 0
        fi
    fi

    echo ""
    echo_fail "observed $record_count records; expected $record_count"
    echo_fail "observed $val_count vals; expected $record_count"
    echo ""

    die_or_fall_through; return 0
}

check_cr()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local shadow_count=$(grep "\- shadow" serial.out | wc -l)
    local val_count=$(grep "\- val" serial.out | wc -l)

    if [[ $record_count -eq $val_count && $val_count -eq $shadow_count ]];
    then
        if [[ $record_count -gt 0 ]];
        then
            return 0
        else
            echo_fail "observed $record_count records; expected at least one"
            echo ""
            die_or_fall_through; return 0
        fi
    fi

    echo ""
    echo_fail "observed $record_count records; expected $record_count"
    echo_fail "observed $shadow_count shadows; expected $record_count"
    echo_fail "observed $val_count vals; expected $record_count"
    echo ""

    die_or_fall_through; return 0
}

check_cpuid()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local leaf_count=$(grep "\- leaf" serial.out | wc -l)
    local subleaf_count=$(grep "\- subleaf" serial.out | wc -l)
    local rax_count=$(grep "\- rax" serial.out | wc -l)
    local rbx_count=$(grep "\- rbx" serial.out | wc -l)
    local rcx_count=$(grep "\- rcx" serial.out | wc -l)
    local rdx_count=$(grep "\- rdx" serial.out | wc -l)

    if [[ $record_count -eq $leaf_count && $leaf_count -eq $subleaf_count &&
          $subleaf_count -eq $rax_count && $rax_count -eq $rbx_count &&
          $rbx_count -eq $rcx_count && $rcx_count -eq $rdx_count  &&
          $rdx_count -eq $cpu_count ]];
    then
        return 0
    fi

    echo ""
    echo_fail "observed $record_count records; expected $cpu_count"
    echo_fail "observed $leaf_count leaf; expected $cpu_count"
    echo_fail "observed $subleaf_count subleaf; expected $cpu_count"
    echo_fail "observed $rax_count rax; expected $cpu_count"
    echo_fail "observed $rbx_count rbx; expected $cpu_count"
    echo_fail "observed $rcx_count rcx; expected $cpu_count"
    echo_fail "observed $rdx_count rdx; expected $cpu_count"
    echo ""

    die_or_fall_through; return 0
}

check_ept()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local ept_misconfiguration_count=$(grep ": record" serial.out | wc -l)
    local ept_read_violation_count=$(grep ": data read record" serial.out | wc -l)
    local ept_write_violation_count=$(grep ": data write record" serial.out | wc -l)
    local ept_execute_violation_count=$(grep ": instruction fetch record" serial.out | wc -l)

    if [[ $ept_misconfiguration_count -ne $cpu_count ]];
    then
        echo_fail "observed $ept_misconfiguration_count ept misconfigurations; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    if [[ $ept_read_violation_count -ne $cpu_count ]];
    then
        echo_fail "observed $ept_read_violation_count ept read violations; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    if [[ $ept_write_violation_count -ne $cpu_count ]];
    then
        echo_fail "observed $ept_write_violation_count ept write violations; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi

    if [[ $ept_execute_violation_count -ne $cpu_count ]];
    then
        echo_fail "observed $ept_execute_violation_count ept execute violations; expected $cpu_count"
        echo ""
        die_or_fall_through; return 0
    fi


    return 0
}

check_io()
{
    local record_count=$(grep ": record" serial.out | wc -l)
    local port_count=$(grep "\- port_number" serial.out | wc -l)
    local size_count=$(grep "\- size_of_access" serial.out | wc -l)
    local direction_count=$(grep "\- direction_of_access" serial.out | wc -l)
    local address_count=$(grep "\- address " serial.out | wc -l)
    local val_count=$(grep "\- val" serial.out | wc -l)

    if [[ $record_count -eq $port_count && $port_count -eq $size_count &&
          $size_count -eq $direction_count && $direction_count -eq $address_count &&
          $address_count -eq $val_count ]];
    then
        return 0
    fi

    echo ""
    echo_fail "observed $record_count records; expected $record_count"
    echo_fail "observed $port_count port; expected $record_count"
    echo_fail "observed $size_count size; expected $record_count"
    echo_fail "observed $direction_count direction; expected $record_count"
    echo_fail "observed $address_count address; expected $record_count"
    echo_fail "observed $val_count val; expected $record_count"
    echo ""

    die_or_fall_through; return 0
}

check_test()
{
    local vmm=$1

    case $vmm in
        *_x64_drs*) check_dr;;
        *_x64_cpuid*) check_cpuid;;
        *_x64_control_register*) check_cr;;
        *_x64_ept*) check_ept;;
        *_x64_io_instruction*) check_io;;
        *_x64_monitor_trap*) check_monitor_trap;;
        *_x64_*msr*) check_msr;;
        *_x64_vic*) check_vic;;
        *_x64_vpid*) check_vpid;;
        *_x64_phys_pci*) check_phys_pci;;
        *)
            echo ""
            echo -ne "$bold_yellow"
            echo -e  "ALERT:$reset check not supported: $vmm"
            ;;
    esac
}

#
# Test initializers
#

init_vic()
{
    sudo dmesg -C
}

init_test()
{
    local vmm=$1

    case $vmm in
        *_x64_vic*) init_vic;;
        *) ;;
    esac
}

#
# Prettify the test names
#

parse_test_name()
{
    name=$(basename $1 | sed 's|eapis_integration_intel_x64_\(.*\)_\(.*\)|\1_\2|')
    echo "$name"
}

#
# Test code
#

echo_milestone "Preparing test vmms\n"
echo_task "building test vmms\n"

pushd $build_dir
if [[ -e build.ninja ]];
then
    echo -ne "$bold_red"
    echo -e "ERROR: Only Unix Makefiles supported$reset"
    exit 1
fi

#bash -c "cmake $hyp_src -DCONFIG=$config && make -j$(nproc)"
popd

echo_task "cleaning bfdriver\n"
cmake --build $build_dir --target driver_clean

echo_task "building bfdriver\n"
cmake --build $build_dir --target driver_build

echo_task "loading  bfdriver\n"
cmake --build $build_dir --target driver_load

echo_milestone "Running test vmms\n"
for vmm in $(find $vmm_bin_dir -name "*eapis*integration*" | sort)
do
    echo_task "testing: $(parse_test_name $vmm)"
    init_test $vmm

    sudo $bfm load $vmm
    sudo $bfm start
    sudo $bfm stop
    sudo $bfm dump > serial.out

    check_test $vmm
    check_test_all

    sleep 3

    if [[ $option_keep_dumps -eq 0 ]]
    then
        rm -f serial.out
    else
        mv -f serial.out "serial_$(parse_test_name $vmm).out"
    fi

    echo_pass
    echo ""
done
