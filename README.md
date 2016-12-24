<img src="https://github.com/Bareflank/extended_apis/raw/master/doc/images/bareflank_extended_apis_logo.jpg" width="501">
<br>
<br>
<br>
[![GitHub version](https://badge.fury.io/gh/Bareflank%2Fextended_apis.svg)](https://badge.fury.io/gh/Bareflank%2Fextended_apis)
[![Build Status](https://travis-ci.org/Bareflank/extended_apis.svg?branch=master)](https://travis-ci.org/Bareflank/extended_apis)
[![codecov](https://codecov.io/gh/Bareflank/extended_apis/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/extended_apis)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor)'s main
goal is to provide the "bare" minimum hypervisor. Since Bareflank supports
C++ 11/14, multiple operating systems, and a full toolstack, it's not as
simple as say [SimpleVisor](https://github.com/ionescu007/SimpleVisor),
but still adheres to the same basic principles of leaving out the complexity
of a full blown hypervisor in favor of an implementation that is simple to
read and follow.

It is our goal to provide a hypervisor that others can extend to create
their own hypervisors. To this end, it is likely that when creating your
own hypervisor, some tasks will be redundant. For example, Windows
makes a lot of MSR accesses. When running Bareflank this is obvious as
Windows takes a significant performance penalty
since all MSR accesses are emulated. The first step most people will take
on an Intel platform is to enable VPID and MSR bitmaps to increase
performance. The process of setting up these resources is the same,
regardless of what type of hypervisor you might be creating.

The purpose of this repository, is to provide an extended set of APIs to
build your hypervisors from. Some of these APIs include:

- MSR / IO Bitmaps
- VPID / Extended Page Tables (EPT)
- Event Injection
- Monitor Traps
- [LibVMI](https://github.com/libvmi/libvmi) Support

## Compilation / Usage

To setup the extended_apis, we must clone the extension into the Bareflank
root folder and run make (the following assumes this is running on Linux).

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor
git clone https://github.com/Bareflank/extended_apis.git

./tools/scripts/setup-<xxx>.sh --no-configure
sudo reboot

cd ~/hypervisor
./configure -m ./extended_apis/bin/extended_apis.modules

make
make test
```

To test out the extended version of Bareflank, all we need to do is run the
make shortcuts as usual:

```
make driver_load
make quick

make status
make dump

make stop
make driver_unload
```

There are also a number of tests that can be run that demonstrate the various
different vmcalls that are provided. For example:

```
cd ~/hypervisor
../extended_apis/tests/test_vpid.sh
```

The `test_vpid.sh` enables / disables VPID using JSON based vmcalls on
the bootstrap processor (core 0) as follows

```
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": true}'" make vmcall
ARGS="--cpuid 0 string json '{\"set\":\"vpid\", \"enabled\": false}'" make vmcall
```

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## Roadmap

The project roadmap can be located [here](https://github.com/Bareflank/hypervisor/projects)

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
