//
// Bareflank Hypervisor
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

#ifndef PHYS_PCI_EAPIS_H
#define PHYS_PCI_EAPIS_H

#include <bfexports.h>
#include <vector>
#include "pci_register.h"

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace eapis
{
namespace pci
{

/// Physical PCI device
///
/// This class provides register-level access to a physical PCI
/// device.
class EXPORT_HVE phys_pci
{
public:
    ///
    /// Construct a phys_pci device for a given geographical address. The device
    /// is not required to exist; you can check for the existence of a device by
    /// instantiating it and then checking whether the vendor and device IDs are
    /// 0xFFFF.
    ///
    /// @expects bus <= 255, device <= 31, func <= 7
    /// @ensures
    ///
    /// @param bus PCI bus number
    /// @param device Device number on the bus
    /// @param func Function, for multifunction devices (or 0)
    ///
    phys_pci(bus_type bus, device_type device, func_type func)
        : m_bus(bus),
          m_device(device),
          m_func(func)
    {}

    virtual ~phys_pci() = default;

    /// @brief Get the geographical PCI bus number of this device.
    /// @return Geographical bus number
    inline bus_type bus() const { return m_bus; }

    /// @brief Get the geographical device number of this device.
    /// @return Geographical device number
    inline device_type device() const { return m_device; }

    /// @brief Get the function number of this device.
    /// @return Geographical function number
    inline func_type func() const { return m_func; }

    ///
    /// Enumerate all the PCI devices on this system into a vector. This will
    /// recursively enumerate all bridges.
    ///
    /// @expects
    /// @ensures All devices returned in `vect` exist.
    ///
    /// @param vect a vector to collect devices.
    ///
    static void enumerate(std::vector<phys_pci> &vect);

    /// @brief Get the device (product) ID, or 0xFFFF if the device doesn't exist
    /// @return the device (product) ID, or 0xFFFF if the device doesn't exist
    inline uint16_t device_id() const { return read_register_u16(0x02); }

    /// @brief Get the vendor ID, or 0xFFFF if the device doesn't exist.
    /// @return the vendor ID, or 0xFFFF if the device doesn't exist.
    inline uint16_t vendor_id() const { return read_register_u16(0x00); }

    /// @brief Get the status code
    /// @return the status code
    inline uint16_t status() const { return read_register_u16(0x06); }

    /// @brief Get the contents of the command register
    /// @return the contents of the command register
    inline uint16_t read_command() const { return read_register_u16(0x04); }

    /// @brief Get the device's class
    /// @return the device's class
    inline uint8_t device_class() const { return read_register_u8(0x0B); }

    /// @brief Get the device's subclass
    /// @return the device's subclass
    inline uint8_t device_subclass() const { return read_register_u8(0x0A); }

    /// @brief Get the device's programming interface
    /// @return the device's programming interface
    inline uint8_t prog_if() const { return read_register_u8(0x09); }

    /// @brief Get the device's revision ID
    /// @return the device's revision ID
    inline uint8_t revision() const { return read_register_u8(0x08); }

    /// @brief Get the built-in self test control register
    /// @return the built-in self test control register
    inline uint8_t read_bist() const { return read_register_u8(0x0F); }

    ///
    /// @brief Return the PCI descriptor type.
    ///
    /// The high bit (0x80) indicates whether this is a multifunction device. If
    /// the low seven bits are not 0x00, other register read methods may be
    /// invalid as phys_pci is only implemented for type 0 devices; type 1 and
    /// type 2 devices must be read using the read_register methods directly.
    ///
    /// @return the PCI descriptor type.
    ///
    inline uint8_t header_type() const { return read_register_u8(0x0E); }

    /// @brief Get the device's bus latency
    /// @return the device's bus latency
    inline uint8_t latency() const { return read_register_u8(0x0D); }

    /// @brief Get the system cache line size in 32-bit dwords
    /// @return the system cache line size in 32-bit dwords
    inline uint8_t cl_size() const { return read_register_u8(0x0C); }

    /// @brief Get the Cardbus CIS pointer
    /// @return the Cardbus CIS pointer
    inline uint32_t cisp() const { return read_register_u32(0x28); }

    /// @brief Get the subsystem ID
    /// @return the subsystem ID
    inline uint16_t subsystem_id() const { return read_register_u16(0x2E); }

    /// @brief Get the subsystem vendor ID
    /// @return the subsystem vendor ID
    inline uint16_t subsystem_vid() const { return read_register_u16(0x2C); }

    /// @brief Get the expansion ROM base address register
    /// @return the expansion ROM base address register
    inline uint32_t exprom_bar() const { return read_register_u32(0x30); }

    /// @brief Get the pointer to the capabilities list, if (status() & 0x10) != 0.
    /// @return the pointer to the capabilities list, if (status() & 0x10) != 0.
    inline uint8_t capabilities_ptr() const { return read_register_u8(0x34); }

    /// @brief Get the device's maximum bus latency in 0.25us units
    /// @return the device's maximum bus latency in 0.25us units
    inline uint8_t max_latency() const { return read_register_u8(0x3F); }

    /// @brief Get the device's required burst period in 0.25us units
    /// @return the device's required burst period in 0.25us units
    inline uint8_t min_grant() const { return read_register_u8(0x3E); }

    /// @brief Get the device's interrupt pin
    /// @return the device's interrupt pin
    inline uint8_t int_pin() const { return read_register_u8(0x3D); }

    /// @brief Get the device's interrupt line
    /// @return the device's interrupt line
    inline uint8_t int_line() const { return read_register_u8(0x3C); }

    ///
    /// @brief Return the contents of the specified base address register.
    ///
    /// @expects n < 6
    /// @ensures invalid indices return 0xFFFFFFFF
    ///
    /// @param n index of the desired base address register
    ///
    /// @return contents of the specified base address register, or 0xFFFFFFFF for invalid indices
    ///
    inline uint32_t bar(unsigned int n) const
    {
        if (n < 6) {
            return read_register_u32(0x10 + 4 * n);
        }
        else {
            return 0xFFFFFFFF;
        }
    }

    /// @brief Return the secondary bus if this is a bridge, or 0 otherwise.
    /// @return secondary bus or 0
    inline uint8_t secondary_bus() const
    {
        if ((header_type() & 0x7F) == 1) {
            return read_register_u8(0x19);
        }
        else {
            return 0;
        }
    }

    /// Write a command to the device's command register
    /// @param command command register contents
    inline void send_command(uint16_t command) { rmw_register_u16(0x04, command); }

    /// Write a built-in self test command to the device's BIST register
    /// @param value BIST register contents
    inline void send_bist(uint8_t value) { rmw_register_u8(0x0F, value); }

    /// Set the device's bus latency in PCI bus clocks
    /// @param cycles bus latency in PCI bus clocks
    inline void set_latency(uint8_t cycles) { rmw_register_u8(0x0D, cycles); }

    /// Set the system cache line size in 32-bit dwords
    /// @param n_dwords cache line size in 32-bit dwords
    inline void set_cl_size(uint8_t n_dwords) { rmw_register_u8(0x0C, n_dwords); }

    /// Set the expansion ROM base address register
    /// @param value expansion ROM base address register contents
    inline void set_exprom_bar(uint32_t value) { write_register(0x30, value); }

    /// Set the device's interrupt line
    /// @param line interrupt line
    inline void set_int_line(uint8_t line) { rmw_register_u8(0x3C, line); }

    ///
    /// @brief Set the contents of the specified base address register.
    ///
    /// @expects n < 6
    /// @ensures invalid indices cause no write
    ///
    /// @param n index of the desired base address register
    /// @param value value to write
    ///
    inline void set_bar(unsigned int n, uint32_t value)
    {
        if (n < 6) {
            write_register(0x10 + 4 * n, value);
        }
    }

    ///
    /// @brief Read 8 bits from a register.
    ///
    /// @expects reg <= 0x3F
    /// @ensures
    ///
    /// @param reg register index in bytes
    ///
    /// @return contents of the register
    ///
    inline uint8_t read_register_u8(register_type reg) const
    {
        return pci::read_register_u8(m_bus, m_device, m_func, reg);
    }

    ///
    /// @brief Read 16 bits from a register.
    ///
    /// @expects reg <= 0x3F and reg is 16-bit aligned
    /// @ensures
    ///
    /// @param reg register index in bytes
    ///
    /// @return contents of the register
    ///
    inline uint16_t read_register_u16(register_type reg) const
    {
        return pci::read_register_u16(m_bus, m_device, m_func, reg);
    }

    ///
    /// @brief Read 32 bits from a register.
    ///
    /// @expects reg <= 0x3F and reg is 32-bit aligned
    /// @ensures
    ///
    /// @param reg register index in bytes
    ///
    /// @return contents of the register
    ///
    inline uint32_t read_register_u32(register_type reg) const
    {
        return pci::read_register_u32(m_bus, m_device, m_func, reg);
    }

    ///
    /// @brief Write 32 bits to a register.
    ///
    /// @expects reg <= 0x3F and reg is 32-bit aligned
    /// @ensures
    ///
    /// @param reg register index in bytes
    /// @param val value to write
    ///
    void write_register(register_type reg, uint32_t val)
    {
        pci::write_register(m_bus, m_device, m_func, reg, val);
    }

    ///
    /// @brief Perform an 8-bit read-modify-write operation on a 32-bit register.
    ///
    /// @expects reg <= 0x3F
    /// @ensures
    ///
    /// @param reg register index in bytes
    /// @param val value to write
    ///
    void rmw_register_u8(register_type reg, uint8_t val)
    {
        pci::rmw_register_u8(m_bus, m_device, m_func, reg, val);
    }

    ///
    /// @brief Perform a 16-bit read-modify-write operation on a 32-bit register.
    ///
    /// @expects reg <= 0x3F and reg is 16-bit aligned
    /// @ensures
    ///
    /// @param reg register index in bytes
    /// @param val value to write
    ///
    void rmw_register_u16(register_type reg, uint16_t val)
    {
        pci::rmw_register_u16(m_bus, m_device, m_func, reg, val);
    }

protected:

    /// Geographical bus number
    bus_type m_bus;

    /// Geographical device number
    device_type m_device;

    /// Geographical function number
    func_type m_func;

};

///
/// @brief Class providing detailed access to base address registers
///
class EXPORT_HVE bar
{
public:

    /// @brief Type of address contained in this BAR
    enum bar_type {
        /// BAR containing a 32-bit address into physical memory
        bar_memory_32bit,

        /// BAR containing a 64-bit address into physical memory. This type
        /// also consumes the next BAR.
        bar_memory_64bit,

        /// BAR containing a 32-bit address into IO space
        bar_io,

        /// Invalid BAR. BARs can be invalid for two reasons: either they
        /// are consumed as the high half of a 64-bit BAR, or the specified
        /// BAR index does not exist in this device's header type.
        bar_invalid,
    };

    /// Instantiate a BAR from a PCI device and a BAR index.
    ///
    /// @param device existing PCI device
    /// @param index BAR index. Valid indices are always less than 6; not all
    ///         BAR indices will be valid for a given device so the user must
    ///         check type().
    bar(phys_pci device, unsigned int index)
        : m_device(device),
          m_index(index)
    {
        m_type = compute_type();
    }

    virtual ~bar() = default;

    /// Get the type of this BAR
    /// @return BAR type
    inline enum bar_type type() const { return m_type; }

    /// Get the base address of this BAR
    /// @return BAR physical base address
    uintptr_t base_address() const;

    /// @brief Get the length of this BAR's memory region.
    /// This is not const because it must write to the BAR to query.
    /// @return memory/IO region length in bytes
    size_t region_length();

    /// @brief Get whether this region is prefetchable.
    /// Always returns false for IO BARs.
    /// @return true iff prefetchable
    bool prefetchable() const;

    /// @brief Set the base address of this BAR
    /// @param address BAR base address. Must be aligned as required for this BAR's type
    void set_base_address(uintptr_t address);

private:

    /// Device containing this BAR
    phys_pci m_device;

    /// Index of BAR
    unsigned int m_index;

    /// Type of BAR. Stored because it is needed frequently and somewhat expensive to compute
    enum bar_type m_type;

    /// Compute the BAR type.
    enum bar_type compute_type() const;

    /// Compute the memory region length for 64-bit only
    size_t region_length_64();

    /// Return the bitmask of address bits for this BAR type
    uint32_t mask() const;
};


}
}

#endif
