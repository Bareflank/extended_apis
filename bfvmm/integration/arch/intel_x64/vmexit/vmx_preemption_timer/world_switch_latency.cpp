//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
    uint64_t m_start{};
    uint64_t m_end{};
    uint64_t m_count{};

    std::list<uint64_t> m_sample;

public:
    explicit vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->add_preemption_timer_handler(
            preemption_timer_handler::handler_delegate_t::create <
            vcpu, &vcpu::handler > (this)
        );

        if (!eapis::intel_x64::time::invariant_tsc_supported()) {
            return;
        }

        this->enable_preemption_timer();
        this->set_preemption_timer(0);

        m_start = ::x64::read_tsc::get();
    }

    bool handler(gsl::not_null<vcpu_t *> vcpu)
    {
        bfignored(vcpu);

        m_end = ::x64::read_tsc::get();
        m_count++;

        if (m_count > SAMPLE_SIZE) {
            this->disable_preemption_timer();
            return true;
        }

        m_sample.push_front(m_end - m_start);
        m_start = ::x64::read_tsc::get();

        return true;
    }

    ~vcpu() override
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

        if (ticks_per_usec != 0) {
            bfdebug_ndec(0, "BUS (MHz)", bus);
            bfdebug_ndec(0, "TSC (MHz)", eapis::intel_x64::time::tsc_freq_MHz(bus));
            bfdebug_ndec(0, "Avg vmentry->vmexit latency (us)", tsc / ticks_per_usec);
            bfdebug_ndec(0, "Avg vmentry->vmexit latency TSC ticks", tsc);
            bfdebug_ndec(0, "Avg vmentry->vmexit latency PET ticks", tsc >> div);
        }
    }

public:

    /// @cond

    vcpu(vcpu &&) = delete;
    vcpu &operator=(vcpu &&) = delete;

    vcpu(const vcpu &) = delete;
    vcpu &operator=(const vcpu &) = delete;

    /// @endcond
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
