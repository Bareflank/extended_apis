#include <exit_handler/exit_handler_intel_x64_eapis.h>

#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <intrinsics/crs_intel_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

using cr0_value_type = intel_x64::cr0::value_type;
using cr3_value_type = intel_x64::cr3::value_type;
using cr4_value_type = intel_x64::cr4::value_type;
using cr8_value_type = intel_x64::cr8::value_type;

// get_gpr_value_by_index_reg
//
// This function resolves the value of the guest gpr by accessing the correct state save field
// according to the ordering dictated by the Intel manual.
// This ordering is the same as defined by the exit_qualification::control_register_access::general_purpose_register namespace,
// and therefore it will be used.
// The state save is currently ordered by System V's ordering, and thus there must be a transition using a switch-case statement or similar.
// Let the ordering of the state save ever be changed to fit the Intel ordering, this function should be replaced to use gsl::span or pointer arithmetics,
// as that would increase performance.
vmcs::value_type exit_handler_intel_x64_eapis::get_gpr_value_by_index_reg(vmcs::value_type index_gpr)
{
    using namespace exit_qualification::control_register_access;
    using namespace access_type;
    using namespace general_purpose_register;

    switch (index_gpr)
    {
        case general_purpose_register::rax:
            return m_state_save->rax;

        case general_purpose_register::rcx:
            return m_state_save->rcx;


        case general_purpose_register::rdx:
            return m_state_save->rdx;


        case general_purpose_register::rbx:
            return m_state_save->rbx;


        case general_purpose_register::rsp:
            return m_state_save->rsp;


        case general_purpose_register::rbp:
            return m_state_save->rbp;


        case general_purpose_register::rsi:
            return m_state_save->rsi;


        case general_purpose_register::rdi:
            return m_state_save->rdi;


        case general_purpose_register::r8:
            return m_state_save->r08;


        case general_purpose_register::r9:
            return m_state_save->r09;


        case general_purpose_register::r10:
            return m_state_save->r10;


        case general_purpose_register::r11:
            return m_state_save->r11;


        case general_purpose_register::r12:
            return m_state_save->r12;


        case general_purpose_register::r13:
            return m_state_save->r13;

        case general_purpose_register::r14:
            return m_state_save->r14;

        case general_purpose_register::r15:
            return m_state_save->r15;
    }

    return 0;
}

// set_gpr_value_by_index_reg
//
// This function is the parallel set function to get_gpr_value_by_index_reg;
// read it's documentation to better understand it.
void exit_handler_intel_x64_eapis::set_gpr_value_by_index_reg(uint64_t index_gpr, vmcs::value_type new_value)
{
    using namespace exit_qualification::control_register_access;
    using namespace access_type;
    using namespace general_purpose_register;

    switch (index_gpr)
    {
        case general_purpose_register::rax:
            m_state_save->rax = new_value;
            break;

        case general_purpose_register::rcx:
            m_state_save->rcx = new_value;
            break;

        case general_purpose_register::rdx:
            m_state_save->rdx = new_value;
            break;

        case general_purpose_register::rbx:
            m_state_save->rbx = new_value;
            break;

        case general_purpose_register::rsp:
            m_state_save->rsp = new_value;
            break;

        case general_purpose_register::rbp:
            m_state_save->rbp = new_value;
            break;

        case general_purpose_register::rsi:
            m_state_save->rsi = new_value;
            break;

        case general_purpose_register::rdi:
            m_state_save->rdi = new_value;
            break;

        case general_purpose_register::r8:
            m_state_save->r08 = new_value;
            break;

        case general_purpose_register::r9:
            m_state_save->r09 = new_value;
            break;

        case general_purpose_register::r10:
            m_state_save->r10 = new_value;
            break;

        case general_purpose_register::r11:
            m_state_save->r11 = new_value;
            break;

        case general_purpose_register::r12:
            m_state_save->r12 = new_value;
            break;

        case general_purpose_register::r13:
            m_state_save->r13 = new_value;
            break;

        case general_purpose_register::r14:
            m_state_save->r14 = new_value;
            break;

        case general_purpose_register::r15:
            m_state_save->r15 = new_value;
            break;
    }
}

void
exit_handler_intel_x64_eapis::handle_exit__ctl_reg_access()
{
    using namespace exit_qualification::control_register_access;
    using namespace access_type;
    using namespace general_purpose_register;

    auto cr = control_register_number::get();
    auto type = access_type::get();
    auto index_gpr = general_purpose_register::get();

    switch (cr)
    {
        case 0:
        {
            // Handling cr0 access exits
            // Only cr0 loads can cause VM exits; thus no need to check type.
            // This block does the following:
            //
            // 1. Get the original value the guest software tried to assign
            // 2. Call the hook, and retrive the audited value.
            // 3. Set the new value, thus emulating the instruction
            // 4. Skip the emulated instruction and resume.
            cr0_value_type requested_new_guest_cr0_value = get_gpr_value_by_index_reg(index_gpr);

            uint64_t audited_new_cr0_value = m_vmcs_eapis->cr0_load_callback(requested_new_guest_cr0_value);
            vmcs::guest_cr0::set(audited_new_cr0_value);

            this->advance_and_resume();
            return;
        }

        case 3:
        {
            switch (type)
            {
                case mov_to_cr:
                {
                    // Handling cr3 load exits
                    // This block does the following:
                    //
                    // 1. Get the original value the guest software tried to assign
                    // 2. Call the hook, and retrive the audited value.
                    // 3. Set the new value, thus emulating the instruction
                    // 4. Skip the emulated instruction and resume.
                    cr3_value_type requested_new_guest_cr3_value = get_gpr_value_by_index_reg(index_gpr);

                    uint64_t audited_new_cr3_value = m_vmcs_eapis->cr3_load_callback(requested_new_guest_cr3_value);
                    vmcs::guest_cr3::set(audited_new_cr3_value);

                    this->advance_and_resume();
                    return;
                }
                case mov_from_cr:
                {
                    // Handling cr3 store exits
                    // This block does the following:
                    //
                    // 1. Get the real cr3 value
                    // 2. Call the hook, and retrive the shadow value.
                    // 3. Set the shadow value to the gpr, thus emulating the instruction
                    // 4. Skip the emulated instruction and resume.
                    cr3_value_type real_guest_cr3_value = vmcs::guest_cr3::get();

                    uint64_t shadow_cr3_value = m_vmcs_eapis->cr3_store_callback(real_guest_cr3_value);

                    set_gpr_value_by_index_reg(index_gpr, shadow_cr3_value);

                    this->advance_and_resume();
                    return;
                }
            }
        }
        case 4:
        {
            // Handling cr4 access exits
            // Only cr4 loads can cause VM exits; thus no need to check type.
            // This block does the following:
            //
            // 1. Get the original value the guest software tried to assign
            // 2. Call the hook, and retrive the audited value.
            // 3. Set the new value, thus emulating the instruction
            // 4. Skip the emulated instruction and resume.
            cr4_value_type requested_new_guest_cr4_value = get_gpr_value_by_index_reg(index_gpr);

            uint64_t audited_new_cr4_value = m_vmcs_eapis->cr4_load_callback(requested_new_guest_cr4_value);
            vmcs::guest_cr4::set(audited_new_cr4_value);

            this->advance_and_resume();
            return;
        }
        case 8:
        {
            switch (type)
            {
                case mov_to_cr:
                {
                    // Handling cr8 loads exits
                    // This block does the following:
                    //
                    // 1. Get the original value the guest software tried to assign
                    // 2. Call the hook, and retrive the audited value.
                    // 3. Set the new value, thus emulating the instruction
                    // 4. Skip the emulated instruction and resume.
                    cr8_value_type requested_new_guest_cr8_value = get_gpr_value_by_index_reg(index_gpr); // Get the original value the guest software tried to assign

                    uint64_t audited_new_cr8_value = m_vmcs_eapis->cr8_load_callback(requested_new_guest_cr8_value); // Call the hook, and retrive the audited value.
                    intel_x64::cr8::set(audited_new_cr8_value); // Set the new value, thus emulating the instruction

                    this->advance_and_resume(); // Skip the emulated instruction and resume.
                    return;
                }
                case mov_from_cr:
                {
                    // Handling cr8 store exits
                    // This block does the following:
                    //
                    // 1. Get the real cr8 value
                    // 2. Call the hook, and retrive the shadow value.
                    // 3. Set the shadow value to the gpr, thus emulating the instruction
                    // 4. Skip the emulated instruction and resume.
                    cr8_value_type real_guest_cr8_value = intel_x64::cr8::get();

                    uint64_t shadow_cr8_value = m_vmcs_eapis->cr8_store_callback(real_guest_cr8_value); // Call the hook, and retrive the shadow value.
                    set_gpr_value_by_index_reg(index_gpr, shadow_cr8_value); // Set the shadow value to the gpr, thus emulating the instruction

                    this->advance_and_resume(); // Skip the emulated instruction and resume.
                    return;
                }
            }
        }

        default:
            bferror << "unimplemented control register access" << bfendl;
            break;
    }
}
