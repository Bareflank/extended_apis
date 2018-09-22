![Extended APIs](https://github.com/Bareflank/extended_apis/raw/v1.1.0/doc/images/bareflank_extended_apis_logo.jpg)

<br>
<br>
<br>

[![GitHub Version](https://badge.fury.io/gh/bareflank%2Fextended_apis.svg)](https://badge.fury.io/gh/bareflank%2Fextended_apis)
[![Build Status](https://travis-ci.org/Bareflank/extended_apis.svg?branch=master)](https://travis-ci.org/Bareflank/extended_apis)
[![Build status](https://ci.appveyor.com/api/projects/status/xhnjkb9lh97tjagt?svg=true)](https://ci.appveyor.com/project/rianquinn/extended-apis)
[![codecov](https://codecov.io/gh/Bareflank/extended_apis/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/extended_apis)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ca689e94dfed490da4eacce1c6a20ea0)](https://www.codacy.com/app/rianquinn/extended_apis?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Bareflank/extended_apis&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor) is an
open source, hypervisor Software Development Toolkit (SDK), led by
Assured Information Security, Inc. (AIS), that provides a set of APIs needed to
rapidly prototype and create new hypervisors. To ease development, Bareflank
is written in C/C++, and includes support for C++ exceptions, JSON, the GSL
and the C++ Standard Template Library (STL).

The purpose of this repository, is to provide an extended set of APIs to
build your hypervisors from. Some of these APIs include:

- MSR / IO Bitmaps
- VPID / Extended Page Tables (EPT)
- Monitor Traps
- Virtual APIC / Interrupt Management
- Improved UEFI support

## Compilation / Usage

To setup our extension, run the following:

```
git clone https://github.com/Bareflank/hypervisor
git clone https://github.com/Bareflank/extended_apis
mkdir build; cd build
cmake ../hypervisor -DDEFAULT_VMM=eapis_vmm -DEXTENSION=../extended_apis
make -j<# cores + 1>
```

To test out our extended version of Bareflank, run the following commands:

```
make driver_quick
make quick
```

to reverse this:

```
make unload
make driver_unload
```

## Links

[Bareflank Hypervisor Website](http://bareflank.github.io/hypervisor/) <br>
[Bareflank Hypervisor API Documentation](http://bareflank.github.io/hypervisor/html/)

## License

The Bareflank Hypervisor is licensed under the GNU Lesser General Public License
v2.1 (LGPL).
