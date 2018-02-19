#!/bin/bash

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

#
# A helper script to initialize exit handler boilerplate
#

set -e

if [ $# -ne 1 ];
then
    echo "USAGE: <eapis-src>/scrpts/make-hdlr.sh <handler class name>"
    exit 1
fi

if [ ! -d scripts ];
then
    echo "ERROR: Please ./scripts/make-hdlr.sh <name> from the src root"
    exit 1
fi

INC=include/hve/arch/intel_x64/exit_handler
SRC=src/hve/arch/intel_x64/exit_handler

lower=$1
upper=$(echo $1 | awk '{print toupper($0)}')

cp -vn scripts/hdlr_tmpl.h $INC/$lower.h
cp -vn scripts/hdlr_tmpl.cpp $SRC/$lower.cpp

sed -i "s|CLASS|$lower|g" $SRC/$lower.cpp
sed -i "s|CLASS|$lower|g" $INC/$lower.h

sed -i "s|ifndef "$lower"\(.*\)|ifndef "$upper"_HDLR\1|"  $INC/$lower.h
sed -i "s|define "$lower"\(.*\)|define "$upper"_HDLR\1|"  $INC/$lower.h
