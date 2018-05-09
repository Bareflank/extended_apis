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

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/vcpu/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/ept.h>

namespace ept = eapis::intel_x64::ept;
namespace vmcs = ::intel_x64::vmcs;

using namespace eapis::intel_x64;

const uint64_t page_size_bytes = 0x40000000ULL;
const uint64_t page_count = 0x40ULL;

// -----------------------------------------------------------------------------
// vCPU
// -----------------------------------------------------------------------------

namespace test
{

class vcpu : public eapis::intel_x64::vcpu
{

public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vcpu(vcpuid::type id) :
        eapis::intel_x64::vcpu{id}
    {
        this->register_ept_handlers();
        this->enable_ept();
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

private:

    std::unique_ptr<ept::memory_map> m_mem_map;
    bool m_have_trapped_write_violation = false;

private:

    void register_ept_handlers()
    {
        auto hve = this->hve();

        hve->add_ept_read_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_read_violation>(this)
        );

        hve->add_ept_write_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_write_violation>(this)
        );

        hve->add_ept_execute_violation_handler(
            eapis::intel_x64::ept_violation::handler_delegate_t::create<vcpu, &vcpu::handle_execute_violation>(this)
        );

        hve->add_ept_misconfiguration_handler(
            eapis::intel_x64::ept_misconfiguration::handler_delegate_t::create<vcpu, &vcpu::handle_ept_misconfiguration>(this)
        );

        hve->ept_misconfiguration()->enable_log();
        hve->ept_violation()->enable_log();
    }

    void enable_ept()
    {
        m_mem_map = std::make_unique<ept::memory_map>();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            ept::identity_map_1g(*m_mem_map, addr);
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::disable(entry);
            ept::epte::write_access::enable(entry);
            ept::epte::execute_access::disable(entry);
        }

        auto eptp = ept::eptp(*m_mem_map);
        vmcs::ept_pointer::set(eptp);
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
    }

    bool handle_ept_misconfiguration(
        gsl::not_null<vmcs_t *> vmcs,
        eapis::intel_x64::ept_misconfiguration::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::enable(entry);
            ept::epte::write_access::enable(entry);
            ept::epte::execute_access::disable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }

    bool handle_read_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        return true;
    }

    bool handle_write_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        if (m_have_trapped_write_violation) {
            return true;
        }

        m_have_trapped_write_violation = true;
        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::disable(entry);
            ept::epte::write_access::disable(entry);
            ept::epte::execute_access::enable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }

    bool handle_execute_violation(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info)
    {
        bfignored(vmcs);
        bfignored(info);

        info.ignore_advance = true;
        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::disable();

        for (auto i = 0ULL; i < page_count; i++) {
            auto addr = i * page_size_bytes;
            auto &entry = m_mem_map->gpa_to_epte(addr);

            ept::epte::read_access::enable(entry);
            ept::epte::write_access::disable(entry);
            ept::epte::execute_access::enable(entry);
        }

        vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();

        return true;
    }
};

}

// -----------------------------------------------------------------------------
// vCPU Factory
// -----------------------------------------------------------------------------

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<test::vcpu>(vcpuid);
}

}
