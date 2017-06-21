//
// Bareflank Extended APIs
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef BITMANIP_EXT_H
#define BITMANIP_EXT_H

#include <bfgsl.h>
#include <type_traits>

template<
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<B>::value>
    >
auto
set_bit_from_span(gsl::span<T> &view, B b)
{
    auto &&byte_view = gsl::as_writeable_bytes(view);
    byte_view.at(b >> 3) |= gsl::narrow_cast<gsl::byte>((1 << (b & 7)));
}

template<
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<B>::value>
    >
auto
clear_bit_from_span(gsl::span<T> &view, B b)
{
    auto &&byte_view = gsl::as_writeable_bytes(view);
    byte_view.at(b >> 3) &= gsl::narrow_cast<gsl::byte>(~(1 << (b & 7)));
}

template<
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<B>::value>
    >
auto
get_bit_from_span(const gsl::span<T> &view, B b)
{
    auto &&byte_view = gsl::as_writeable_bytes(view);
    return byte_view.at(b >> 3) & gsl::narrow_cast<gsl::byte>((1 << (b & 7)));
}

template<
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<B>::value>
    >
auto
is_bit_set_from_span(T t, B b)
{ return get_bit_from_span(t, b) != gsl::narrow_cast<gsl::byte>(0); }

template<
    typename T,
    typename B,
    typename = std::enable_if<std::is_integral<B>::value>
    >
auto
is_bit_cleared_from_span(T t, B b)
{ return get_bit_from_span(t, b) == gsl::narrow_cast<gsl::byte>(0); }

#endif
