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

#include <list>
#include <algorithm>

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/hve/arch/intel_x64/time.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

#ifndef SAMPLE_SIZE
#define SAMPLE_SIZE 256
#endif

class vcpu : public eapis::intel_x64::vcpu
{
    uint64_t m_start{0};
    uint64_t m_end{0};
    uint64_t m_count;

    std::list<uint64_t> m_sample;

public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->add_vmx_preemption_timer_handler(
            vmx_preemption_timer_handler::handler_delegate_t::create<
            vcpu, &vcpu::handler>(this)
        );

        if (!eapis::intel_x64::time::invariant_tsc_supported()) {
            return;
        }

        this->enable_vmx_preemption_timer();
        this->set_vmx_preemption_timer(0);

        m_start = ::x64::read_tsc::get();
    }

    bool handler(gsl::not_null<vcpu_t *> vcpu)
    {
        bfignored(vcpu);

        m_end = ::x64::read_tsc::get();
        m_count++;

        if (m_count > SAMPLE_SIZE) {
            this->disable_vmx_preemption_timer();
            return true;
        }

        m_sample.push_front(m_end - m_start);
        m_start = ::x64::read_tsc::get();

        return true;
    }

    ~vcpu()
    {
        uint64_t sum = 0;
        for (const auto &sample : m_sample) {
            sum += sample;
        }

        uint64_t tsc = sum >> 8; // Divide by SAMPLE_SIZE
        uint64_t ticks_per_usec = eapis::intel_x64::time::pet_freq_MHz();
        uint64_t div = ::intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();
        uint64_t bus = eapis::intel_x64::time::bus_freq_MHz();

        // NOTE: we should try to avoid / here. We could use multiplies and shifts
        // or we could start a static table of 'ticks_per_usec', and then at initialization
        // assign a conversion function that has compile-time constants so the compiler
        // will do the mult/shift for us.

        bfdebug_ndec(0, "BUS (MHz)", bus);
        bfdebug_ndec(0, "TSC (MHz)", eapis::intel_x64::time::tsc_freq_MHz(bus));
        bfdebug_ndec(0, "Avg vmentry->vmexit latency (us)", tsc / ticks_per_usec);
        bfdebug_ndec(0, "Avg vmentry->vmexit latency TSC ticks", tsc);
        bfdebug_ndec(0, "Avg vmentry->vmexit latency PET ticks", tsc >> div);
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
