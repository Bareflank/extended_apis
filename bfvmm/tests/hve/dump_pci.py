#!/usr/bin/env python3
#
# Bareflank Extended APIs
#
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

import os

devices = sorted(os.listdir("/sys/bus/pci/devices"))

for devname in devices:
    _, bus, devfunc = devname.split(":")
    dev, func = devfunc.split(".")
    bus = int(bus, 16)
    dev = int(dev, 16)
    func = int(func, 16)

    config_path = os.path.join("/sys/bus/pci/devices", devname, "config")

    print("{ 0x%02x, 0x%02x, 0x%02x, {" % (bus, dev, func))

    with open(config_path, "rb") as f:
        for i in range(16):
            n = int.from_bytes(f.read(4), byteorder='little')

            if i % 4 == 0:
                print("   ", end='')

            print(" 0x%08x," % n, end='')

            if i % 4 == 3:
                print()

    print("}},")
