//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef INTERRUPT_QUEUE_INTEL_X64_EAPIS_H
#define INTERRUPT_QUEUE_INTEL_X64_EAPIS_H

#include <queue>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EAPIS_HVE
#ifdef SHARED_EAPIS_HVE
#define EXPORT_EAPIS_HVE EXPORT_SYM
#else
#define EXPORT_EAPIS_HVE IMPORT_SYM
#endif
#else
#define EXPORT_EAPIS_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace eapis::intel_x64
{

class EXPORT_EAPIS_HVE interrupt_queue
{
public:

    using vector_t = uint64_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    interrupt_queue();

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_queue() = default;

    /// Push
    ///
    /// Add an interrupt vector to the queue
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector number to add to the queue
    ///
    void push(vector_t vector);

    /// Pop
    ///
    /// Removes a vector from the queue, and returns it.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the removed vector or throws if the queue
    ///     is empty
    ///
    vector_t pop();

    /// Empty
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the removed vector or throws if the queue
    ///     is empty
    ///
    bool empty() const;

private:

    std::queue<uint64_t> m_vectors;

public:

    /// @cond

    interrupt_queue(interrupt_queue &&) = default;
    interrupt_queue &operator=(interrupt_queue &&) = default;

    interrupt_queue(const interrupt_queue &) = delete;
    interrupt_queue &operator=(const interrupt_queue &) = delete;

    /// @endcond
};

}

#endif
