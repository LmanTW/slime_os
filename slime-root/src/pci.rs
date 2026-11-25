//! Binding one declared PCI function on qemu-arm-virt.
//!
//! The generation declares the function's address and identity on its
//! io-resource budget entry (`contracts/io-resource/v2`). The root reads the
//! identity from that function's configuration space and writes nothing to a
//! function whose identity differs. On a match it sizes BAR 0, places it at the
//! base of the 32-bit memory window, routes its INTx pin, and enables memory
//! decoding only: bus mastering stays off, because this binding grants no DMA.
//!
//! Only the root reads or writes configuration space. A driver receives the
//! BAR as an MMIO region and the INTx route as an interrupt source; it never
//! learns the function's address, the BAR's physical address or the IRQ number.

use boot_contracts::io_resource::PciFunction;

/// Bytes of one function's configuration space in ECAM.
pub const CONFIG_BYTES: usize = 4096;

/// qemu-arm-virt's PCIe host, as its device tree states it. These are pinned
/// machine facts, as the virtio-mmio window is, not discovery.
pub mod arm_virt {
    /// ECAM base of `pcie@10000000`, covering buses 0 to 255.
    pub const ECAM_BASE: usize = 0x40_1000_0000;
    pub const ECAM_BYTES: usize = 0x1000_0000;
    /// The 32-bit memory window; PCI and CPU addresses are equal in it.
    pub const MEM32_BASE: usize = 0x1000_0000;
    pub const MEM32_BYTES: usize = 0x2EFF_0000;
    /// seL4 IRQ of INTA on device 0: GIC SPI 3, so INTID 35. The host's
    /// `interrupt-map` rotates the four INTx lines by device number.
    pub const INTX_FIRST_IRQ: u64 = 35;
}

const ID: usize = 0x00;
const COMMAND: usize = 0x04;
const BAR0: usize = 0x10;
const BAR1: usize = 0x14;
const INTERRUPT_LINE: usize = 0x3C;

/// The command value a bound function holds: memory decoding, nothing else.
pub const COMMAND_MEMORY: u16 = 0x0002;

/// Register access to one function's configuration space.
pub trait ConfigSpace {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}

/// What binding one function produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    /// BAR 0's physical address and size, both multiples of 4 KiB.
    pub address: usize,
    pub size: usize,
    /// Whether BAR 0 is a 64-bit memory BAR.
    pub wide: bool,
    /// The seL4 IRQ number of the function's INTx route.
    pub irq: u64,
    /// The command register value after binding.
    pub command: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindError {
    /// The function holds another identity; nothing was written.
    Identity { found: u32 },
    /// The function is not on bus 0, the only bus this host binding routes.
    Bus,
    /// BAR 0 is absent, an I/O BAR, or smaller than a granule.
    Bar,
    /// BAR 0 does not fit the 32-bit window.
    Window,
    /// The function has no interrupt pin.
    Interrupt,
}

/// Byte offset of `function`'s configuration space within ECAM.
pub const fn ecam_offset(function: &PciFunction) -> usize {
    (function.bus as usize) << 20
        | (function.device as usize) << 15
        | (function.function as usize) << 12
}

/// The seL4 IRQ of INTx `pin` (1 = INTA) on bus 0 device `device`.
pub const fn intx_irq(device: u8, pin: u8) -> u64 {
    arm_virt::INTX_FIRST_IRQ + ((device as u64 + pin as u64 - 1) % 4)
}

/// `vendor:device` as the root's records print it.
pub struct Identity(pub u32);

impl core::fmt::Display for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04x}:{:04x}", self.0 & 0xFFFF, self.0 >> 16)
    }
}

/// `bus:device.function` as the root's records print it.
pub struct Address<'a>(pub &'a PciFunction);

impl core::fmt::Display for Address<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{}",
            self.0.bus, self.0.device, self.0.function
        )
    }
}

/// Bind `declared` through `config`, refusing a BAR 0 larger than `max_size`.
///
/// The identity is read before any write, so a function with another identity
/// leaves this call exactly as it was found. BAR sizing writes all ones and
/// reads the mask back with decoding off, as the PCI specification requires.
/// Every other refusal clears BAR 0, and BAR 1 of a 64-bit BAR, and leaves
/// decoding off, so a refused function decodes nothing.
pub fn bind(
    config: &mut impl ConfigSpace,
    declared: &PciFunction,
    max_size: usize,
) -> Result<Binding, BindError> {
    let found = config.read32(ID);
    if found != declared.identity() {
        return Err(BindError::Identity { found });
    }
    if declared.bus != 0 {
        return Err(BindError::Bus);
    }
    config.write32(COMMAND, 0);
    let original = config.read32(BAR0);
    if original & 0x1 != 0 {
        return Err(BindError::Bar);
    }
    let wide = (original >> 1) & 0x3 == 0x2;
    config.write32(BAR0, u32::MAX);
    let mut mask = u64::from(config.read32(BAR0) & !0xF);
    if wide {
        config.write32(BAR1, u32::MAX);
        mask |= u64::from(config.read32(BAR1)) << 32;
    } else {
        mask |= 0xFFFF_FFFF_0000_0000;
    }
    let size = (!mask).wrapping_add(1) as usize;
    // The window base is 256 MiB aligned, so it is aligned for every BAR that
    // fits; the rule keeps the placement deterministic.
    let address = arm_virt::MEM32_BASE.next_multiple_of(size.max(1));
    let refusal = if mask == 0 {
        Some(BindError::Bar)
    } else if size < CONFIG_BYTES
        || size > max_size
        || address + size > arm_virt::MEM32_BASE + arm_virt::MEM32_BYTES
    {
        Some(BindError::Window)
    } else {
        None
    };
    let pin = ((config.read32(INTERRUPT_LINE) >> 8) & 0xFF) as u8;
    let refusal = refusal.or((!(1..=4).contains(&pin)).then_some(BindError::Interrupt));
    if let Some(error) = refusal {
        config.write32(BAR0, 0);
        if wide {
            config.write32(BAR1, 0);
        }
        return Err(error);
    }
    config.write32(BAR0, address as u32);
    if wide {
        config.write32(BAR1, 0);
    }
    config.write32(COMMAND, u32::from(COMMAND_MEMORY));
    Ok(Binding {
        address,
        size,
        wide,
        irq: intx_irq(declared.device, pin),
        command: config.read32(COMMAND) as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// QEMU's qemu-xhci at 00:03.0: one 16 KiB 64-bit memory BAR and INTA.
    struct Xhci {
        id: u32,
        command: u32,
        bars: [u32; 2],
        writes: usize,
    }

    impl Xhci {
        fn new(id: u32) -> Self {
            Self {
                id,
                command: 0,
                bars: [0x4, 0],
                writes: 0,
            }
        }
    }

    impl ConfigSpace for Xhci {
        fn read32(&mut self, offset: usize) -> u32 {
            match offset {
                ID => self.id,
                COMMAND => self.command | 0x0010_0000,
                BAR0 => self.bars[0],
                BAR1 => self.bars[1],
                INTERRUPT_LINE => 0x0000_0100,
                _ => 0,
            }
        }
        fn write32(&mut self, offset: usize, value: u32) {
            self.writes += 1;
            match offset {
                COMMAND => self.command = value & 0xFFFF,
                BAR0 => self.bars[0] = (value & !0x3FFF) | 0x4,
                BAR1 => self.bars[1] = value,
                _ => {}
            }
        }
    }

    const XHCI: PciFunction = PciFunction {
        bus: 0,
        device: 3,
        function: 0,
        vendor: 0x1B36,
        device_id: 0x000D,
    };

    #[test]
    fn binds_bar_0_at_the_window_base_with_memory_decoding_only() {
        let mut config = Xhci::new(XHCI.identity());
        let binding = bind(&mut config, &XHCI, 0x4000).unwrap();
        assert_eq!(binding.address, arm_virt::MEM32_BASE);
        assert_eq!(binding.size, 0x4000);
        assert!(binding.wide);
        assert_eq!(binding.command, COMMAND_MEMORY);
        assert_eq!(config.bars, [0x1000_0004, 0]);
        // Device 3, INTA: SPI 6, INTID 38, as the host's interrupt-map states.
        assert_eq!(binding.irq, 38);
    }

    #[test]
    fn another_identity_is_refused_before_any_write() {
        let mut config = Xhci::new(0x0005_1B36);
        assert_eq!(
            bind(&mut config, &XHCI, 0x4000),
            Err(BindError::Identity { found: 0x0005_1B36 })
        );
        assert_eq!(config.writes, 0);
    }

    /// A BAR above the root's window is refused before decoding is enabled,
    /// and both halves of the 64-bit BAR are cleared.
    #[test]
    fn a_bar_beyond_the_ceiling_leaves_the_function_decoding_nothing() {
        let mut config = Xhci::new(XHCI.identity());
        assert_eq!(bind(&mut config, &XHCI, 0x2000), Err(BindError::Window));
        assert_eq!(config.command, 0);
        assert_eq!(config.bars, [0x4, 0]);
    }

    #[test]
    fn the_interrupt_route_rotates_by_device() {
        assert_eq!(intx_irq(0, 1), 35);
        assert_eq!(intx_irq(1, 1), 36);
        assert_eq!(intx_irq(3, 1), 38);
        assert_eq!(intx_irq(3, 2), 35);
    }

    #[test]
    fn records_print_the_exam_forms() {
        extern crate alloc;
        use alloc::format;
        assert_eq!(format!("{}", Address(&XHCI)), "00:03.0");
        assert_eq!(format!("{}", Identity(XHCI.identity())), "1b36:000d");
        assert_eq!(ecam_offset(&XHCI), 0x18000);
    }
}
