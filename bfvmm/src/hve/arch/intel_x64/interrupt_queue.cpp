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

#include <bfdebug.h>
#include <hve/arch/intel_x64/interrupt_queue.h>

namespace eapis::intel_x64
{

// For now, this is a simple first in, first out queue. In the future,
// we should implement the priority portion of the interrupt queue that
// the APIC is doing in hardware.
//
// It should be noted that the reason this works is that by the time
// the VMM sees the interrupt, the APIC has already released an interrupt
// with priority in mind, which means in theory, a simple queue is
// sufficient. Incomplete, but sufficient.

void
interrupt_queue::push(vector_t vector)
{ m_vectors.push(vector); }

interrupt_queue::vector_t
interrupt_queue::pop()
{
    auto vector = m_vectors.front();
    m_vectors.pop();

    return vector;
}

bool
interrupt_queue::empty() const
{ return m_vectors.empty(); }

}
