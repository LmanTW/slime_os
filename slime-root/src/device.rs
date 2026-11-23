//! Device MMIO access for `slime-root` (P5.4.2a).
//!
//! The root task holds no ambient device authority. What it has is BootInfo's
//! device untypeds — one per physical region the platform declares — and the
//! same `frame_map` invocation the loader and every windowed syscall already
//! use. This module is the narrow join between them: retype the granule
//! containing a register bank, map it at a root-image address claimed for the
//! purpose, and hand back a volatile view.
//!
//! **Deliberately not a driver.** Nothing here knows what a virtio queue is.
//! The one device-specific thing it does is [`VirtioMmio::probe`], which reads
//! the four registers that say whether a transport is present and what kind it
//! is — because the platform declares thirty-two identical virtio-mmio
//! transports and only probing distinguishes an attached disk from an empty
//! slot. Everything past that identification is userspace policy.
//!
//! The mapping is standing rather than transient, which is why it needs its own
//! root-image page: `transfer_window`'s scratch address is remapped on every
//! staged transfer, so an MMIO frame left there would be replaced by the next
//! one.

use crate::object_allocator::{AllocError, ObjectAllocator};

/// A mapped device register bank.
///
/// Holds the frame capability so the mapping's lifetime is explicit; dropping
/// this does not unmap, because a device the root has bound stays bound for the
/// boot.
pub struct DeviceRegion {
    base: usize,
    paddr: usize,
    #[allow(dead_code)]
    frame: sel4::cap::Granule,
}

/// A borrowed view of an already-mapped device granule (B29, P5.4.3).
///
/// QEMU packs eight virtio-mmio transports into one 4 KiB page, so two attached
/// disks land at `0xa003e00` and `0xa003c00` — the same granule. seL4's retype
/// is monotonic and `frame_map` takes the frame once, so the second transport
/// cannot map it again. What a second driver needs is not another mapping but
/// the same one at its own offset.
///
/// Carries the virtual base and no capability, so it can neither remap nor
/// unmap: the mapping's lifetime stays with the [`DeviceRegion`] it came from,
/// and that region outlives every borrow because a bound device stays bound for
/// the boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedGranule {
    base: usize,
}

impl MappedGranule {
    /// Read a 32-bit register at `offset` within the granule.
    pub fn read32(&self, offset: usize) -> Option<u32> {
        if !offset.is_multiple_of(4) || offset + 4 > GRANULE_BYTES {
            return None;
        }
        // SAFETY: `base` names a granule this root mapped non-cacheably and
        // still holds; the bound keeps the access inside it and the alignment
        // check keeps it aligned.
        Some(unsafe { ((self.base + offset) as *const u32).read_volatile() })
    }

    /// Write a 32-bit register at `offset` within the granule.
    pub fn write32(&self, offset: usize, value: u32) -> bool {
        if !offset.is_multiple_of(4) || offset + 4 > GRANULE_BYTES {
            return false;
        }
        // SAFETY: as `read32`.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) };
        true
    }
}

#[cfg(test)]
impl MappedGranule {
    /// A view of host memory that stands in for a register page.
    pub fn over(page: &mut [u32; GRANULE_BYTES / 4]) -> Self {
        Self {
            base: page.as_mut_ptr() as usize,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    /// The device untyped could not be found or retyped.
    Allocate(AllocError),
    /// `frame_map` refused the mapping.
    Map(sel4::Error),
    /// An interrupt invocation failed: acquisition, binding, or acknowledgement.
    Irq(sel4::Error),
    /// No standing region of the inventory is mapped at that address.
    NoRegion,
    /// The inventory's interrupt slot is out of range or already holds a handle.
    IrqSlot,
}

fn uncached_attributes() -> sel4::VmAttributes {
    #[cfg(target_arch = "aarch64")]
    {
        sel4::VmAttributes::DEFAULT & !sel4::VmAttributes::PAGE_CACHEABLE
    }
    #[cfg(target_arch = "riscv64")]
    {
        sel4::VmAttributes::NONE
    }
    // seL4's x86 attribute word is a cache-policy selector rather than a
    // permission mask: `seL4_X86_Default_VMAttributes` is zero and each policy
    // is a distinct value, so uncached MMIO is `CACHE_DISABLED` outright and
    // not the default with a bit cleared.
    #[cfg(target_arch = "x86_64")]
    {
        sel4::VmAttributes::CACHE_DISABLED
    }
}

impl DeviceRegion {
    /// A borrowed handle on this mapping, for another transport in the same
    /// granule.
    pub const fn granule(&self) -> MappedGranule {
        MappedGranule { base: self.base }
    }

    /// The granule-aligned physical address this region maps.
    ///
    /// Needed to pair a transport with the region holding it once the
    /// transports are sorted into a stable order (P5.4.3).
    pub const fn paddr(&self) -> usize {
        self.paddr
    }
    /// Current virtual address of this frame's mapping.
    pub const fn mapped_base(&self) -> usize {
        self.base
    }
    /// Map this exact device frame into a child VSpace. The caller has already
    /// proved page exclusivity; this function never rounds or widens a region.
    /// A failed map leaves the frame capability owned by this region and marks
    /// it unmapped, so the inventory can retain it for a later retry.
    pub fn map_child(
        &mut self,
        vspace: sel4::cap::VSpace,
        base: usize,
        writable: bool,
    ) -> Result<(), DeviceError> {
        self.frame.frame_unmap().map_err(DeviceError::Map)?;
        self.base = 0;
        let rights = sel4::CapRightsBuilder::none()
            .read(true)
            .write(writable)
            .build();
        self.frame
            .frame_map(vspace, base, rights, uncached_attributes())
            .map_err(DeviceError::Map)?;
        self.base = base;
        Ok(())
    }

    /// Retype the granule containing `paddr` and map it at `base`.
    ///
    /// `base` must be a granule-aligned root-image address already released by
    /// [`crate::child_vspace::ScratchPage::claim`], exactly as the loader's
    /// scratch window is: the root's own image frame for that address must be
    /// unmapped before another frame can take its place.
    pub fn map(
        allocator: &mut ObjectAllocator,
        vspace: sel4::cap::VSpace,
        base: usize,
        paddr: usize,
    ) -> Result<Self, DeviceError> {
        Self::map_tracked(allocator, vspace, base, paddr).map(|(region, _)| region)
    }

    /// As [`Self::map`], also returning the root CSlot index the frame took.
    ///
    /// Needed only by a caller that will [`Self::discard`] the granule: a
    /// `Granule` capability does not carry its own index, so a scanning walk
    /// has to remember it to return it.
    pub fn map_tracked(
        allocator: &mut ObjectAllocator,
        vspace: sel4::cap::VSpace,
        base: usize,
        paddr: usize,
    ) -> Result<(Self, usize), DeviceError> {
        let slot = allocator
            .allocate_device_frame(paddr)
            .map_err(DeviceError::Allocate)?;
        let index = slot.index();
        let frame = slot.cap();
        frame
            .frame_map(
                vspace,
                base,
                sel4::CapRights::read_write(),
                // Device memory must be uncached, or register accesses can be
                // stale or delayed.
                uncached_attributes(),
            )
            .map_err(DeviceError::Map)?;
        Ok((Self { base, paddr, frame }, index))
    }

    pub fn physical_address(&self) -> usize {
        self.paddr
    }

    /// Move this mapping to a different virtual address.
    ///
    /// The frame capability is the same one: a device untyped's page can be
    /// retyped exactly once per boot, so a granule the probe already took is
    /// re-mapped rather than re-acquired.
    pub fn remap(self, vspace: sel4::cap::VSpace, base: usize) -> Result<Self, DeviceError> {
        self.frame.frame_unmap().map_err(DeviceError::Map)?;
        self.frame
            .frame_map(
                vspace,
                base,
                sel4::CapRights::read_write(),
                uncached_attributes(),
            )
            .map_err(DeviceError::Map)?;
        Ok(Self {
            base,
            paddr: self.paddr,
            frame: self.frame,
        })
    }

    /// Release the mapping, leaving `base` free for the next granule.
    ///
    /// The frame capability is not deleted: it names a real MMIO page, and the
    /// space it came from is a device untyped this root has no second use for.
    /// What this frees is the *virtual* window, so one claimed root-image page
    /// can scan a region larger than a granule.
    pub fn unmap(&mut self) -> Result<(), DeviceError> {
        self.frame.frame_unmap().map_err(DeviceError::Map)?;
        self.base = 0;
        Ok(())
    }

    /// Unmap this granule, delete its frame capability, and return its CSlot.
    ///
    /// [`Self::unmap`] deliberately keeps the capability, because a *bound
    /// device* stays bound for the boot and its register bank is read again.
    /// A region merely *scanned* once — a framebuffer written top to bottom —
    /// has the opposite lifetime: retaining a capability per granule spends a
    /// root CSlot and a physical-provenance record per 4 KiB, and the
    /// provenance table is sized for the live DMA-capable population rather
    /// than for a display. A panel-sized walk exhausts it, and the root then
    /// fails to allocate for reasons that have nothing to do with the graph.
    ///
    /// `slot` is the index the allocator returned for this frame. It is passed
    /// rather than derived because a `Granule` capability does not carry its
    /// own root-CSpace index.
    ///
    /// The frame is deleted before the slot is released, which is the order
    /// [`ObjectAllocator::release_slot`] requires: the pool tracks
    /// availability rather than occupancy, so returning an index that still
    /// holds a capability makes the next allocation of it fail `DeleteFirst`.
    ///
    /// [`ObjectAllocator::release_slot`]: crate::object_allocator::ObjectAllocator::release_slot
    pub fn discard(
        mut self,
        allocator: &mut ObjectAllocator,
        slot: usize,
    ) -> Result<(), DeviceError> {
        self.frame.frame_unmap().map_err(DeviceError::Map)?;
        self.base = 0;
        sel4::init_thread::slot::CNODE
            .cap()
            .absolute_cptr(self.frame)
            .delete()
            .map_err(DeviceError::Map)?;
        allocator.release_slot(slot);
        Ok(())
    }

    /// Read one 32-bit register at `offset` bytes into the bank.
    ///
    /// `None` for an offset that would read past the mapped granule, so a
    /// wrong offset is a refusal rather than a read of whatever follows.
    pub fn read32(&self, offset: usize) -> Option<u32> {
        if !offset.is_multiple_of(4) || offset + 4 > GRANULE_BYTES {
            return None;
        }
        // SAFETY: `base` names one granule mapped read-write by `map`, and the
        // bounds check above keeps the access inside it. The read is volatile
        // because the value is produced by a device rather than by memory.
        Some(unsafe { ((self.base + offset) as *const u32).read_volatile() })
    }

    /// Write one 32-bit register. `false` for an out-of-range offset.
    pub fn write32(&self, offset: usize, value: u32) -> bool {
        if !offset.is_multiple_of(4) || offset + 4 > GRANULE_BYTES {
            return false;
        }
        // SAFETY: as `read32`. The write is volatile because it is an effect on
        // a device rather than a store the compiler may elide or reorder.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) };
        true
    }
}

/// The physical address of QEMU `virt`'s PL011 serial controller.
///
/// A fixed address of one machine, not platform discovery. The root maps this
/// page through BootInfo device authority as its own console, under
/// `slime_root_console_pl011`. Under `slime_qemu_keyboard` the same mapping is
/// also the product's terminal input. No other configuration reads the
/// constant.
pub const QEMU_PL011_PADDR: usize = 0x0900_0000;

/// One platform receive adapter behind the root's typed input service.
pub enum TerminalReceiver {
    Pl011(Pl011Input),
    DwApb(DwApbInput),
    #[cfg(target_arch = "x86_64")]
    Com1(Com1Input),
}

impl TerminalReceiver {
    fn poll_byte(&self, buffer: &mut sel4::IpcBuffer) -> Option<u8> {
        match self {
            // Memory-mapped receivers read through a mapped page and reach the
            // kernel not at all, so the buffer is unused on their arms.
            Self::Pl011(receiver) => {
                let _ = &buffer;
                receiver.poll_byte()
            }
            Self::DwApb(receiver) => {
                let _ = &buffer;
                receiver.poll_byte()
            }
            #[cfg(target_arch = "x86_64")]
            Self::Com1(receiver) => receiver.poll_byte(buffer),
        }
    }
}

/// Root-owned terminal input with an optional gate-only control byte.
///
/// The callback is installed only in the P3.F physical-test artifact. The
/// ordinary product has no terminator and forwards every received byte through
/// the declared `InputRead` capability path.
pub struct TerminalInput {
    receiver: TerminalReceiver,
    test_terminator: Option<(u8, fn() -> !)>,
}

impl TerminalInput {
    pub const fn new(receiver: TerminalReceiver) -> Self {
        Self {
            receiver,
            test_terminator: None,
        }
    }

    pub const fn with_test_terminator(mut self, byte: u8, trigger: fn() -> !) -> Self {
        self.test_terminator = Some((byte, trigger));
        self
    }

    pub fn poll_byte(&self, buffer: &mut sel4::IpcBuffer) -> Option<u8> {
        let byte = self.receiver.poll_byte(buffer)?;
        if let Some((terminator, trigger)) = self.test_terminator
            && byte == terminator
        {
            trigger()
        }
        Some(byte)
    }
}

/// Polling receive half of QEMU `virt`'s PL011.
///
/// Output continues through seL4's debug console; this view only drains bytes
/// QEMU delivered on the same serial port. Polling is intentional: `InputRead`
/// already reports `WouldBlock`, so an empty FIFO must not park the root's
/// console dispatcher or require a new interrupt protocol.
pub struct Pl011Input {
    registers: DeviceRegion,
}

impl Pl011Input {
    const DATA: usize = 0x000;
    const FLAGS: usize = 0x018;
    const RX_EMPTY: u32 = 1 << 4;
    const DATA_ERRORS: u32 = 0x0f00;

    pub const fn new(registers: DeviceRegion) -> Self {
        Self { registers }
    }

    /// Drain one received byte, or report an empty FIFO.
    ///
    /// A byte carrying a PL011 receive error is consumed and refused rather
    /// than turned into shell input. The next `InputRead` can then continue
    /// with the following FIFO entry.
    pub fn poll_byte(&self) -> Option<u8> {
        if self.registers.read32(Self::FLAGS)? & Self::RX_EMPTY != 0 {
            return None;
        }
        let data = self.registers.read32(Self::DATA)?;
        if data & Self::DATA_ERRORS != 0 {
            return None;
        }
        Some(data as u8)
    }
}

/// Polling receive half of a 16550-compatible UART with `reg-shift 2` and
/// `reg-io-width 4`. Every board mapped through this adapter must pin that
/// layout, as the Duo's DW-APB UART0 does.
///
/// That shift and width place the receive buffer and line-status registers at
/// byte offsets 0x00 and 0x14 under 32-bit accesses. Firmware owns
/// configuration; this adapter only observes RX state and consumes one byte,
/// leaving the shared debug-console TX path untouched.
pub struct DwApbInput {
    registers: DeviceRegion,
}

impl DwApbInput {
    const RECEIVE_BUFFER: usize = 0x000;
    const LINE_STATUS: usize = 0x014;
    const DATA_READY: u32 = 1 << 0;
    const DATA_ERRORS: u32 = 0x1e;

    pub const fn new(registers: DeviceRegion) -> Self {
        Self { registers }
    }

    pub fn poll_byte(&self) -> Option<u8> {
        let status = self.registers.read32(Self::LINE_STATUS)?;
        if status & Self::DATA_READY == 0 {
            return None;
        }
        if status & Self::DATA_ERRORS != 0 {
            return None;
        }
        let data = self.registers.read32(Self::RECEIVE_BUFFER)?;
        Some(data as u8)
    }
}

/// Polling receive half of the pc99 COM1 16550A, over an I/O-port capability.
///
/// The same register layout as the DW APB adapter above, at a stride of one
/// byte and reached through `in` rather than a load: x86 legacy serial is not
/// memory-mapped, so the root holds a capability over the port range instead of
/// a mapped page. Firmware and seL4's own debug console have already configured
/// the line; this adapter only observes RX state and consumes one byte, leaving
/// the shared TX path untouched.
///
/// A refused invocation is reported as an empty FIFO rather than escalated. The
/// capability is issued once at startup and the port is fixed, so the only way
/// to reach that arm is a kernel-side refusal, and turning a transient refusal
/// into a fatal would take down a resident graph over one dropped keystroke.
#[cfg(target_arch = "x86_64")]
pub struct Com1Input {
    ports: sel4::cap::IOPort,
    base: u16,
}

#[cfg(target_arch = "x86_64")]
impl Com1Input {
    const RECEIVE_BUFFER: u16 = 0;
    const LINE_STATUS: u16 = 5;
    const DATA_READY: u8 = 1 << 0;
    /// Overrun, parity, framing, and break, as the 16550 line-status register
    /// reports them. A byte arriving with any of these set is consumed and
    /// refused rather than turned into shell input.
    const DATA_ERRORS: u8 = 0x1e;

    pub const fn new(ports: sel4::cap::IOPort, base: u16) -> Self {
        Self { ports, base }
    }

    pub fn poll_byte(&self, buffer: &mut sel4::IpcBuffer) -> Option<u8> {
        // Every invocation names this thread's own buffer: the console
        // dispatcher never calls `set_ipc_buffer`, so borrowing the crate's
        // ambient buffer here would panic rather than read a key.
        let status = self
            .ports
            .with(&mut *buffer)
            .ioport_in8(self.base + Self::LINE_STATUS)
            .ok()?;
        if status & Self::DATA_READY == 0 {
            return None;
        }
        // Consume the byte before judging it: a framing or parity error still
        // occupies the FIFO, so returning without reading would wedge the port
        // on the first bad byte instead of skipping it.
        let data = self
            .ports
            .with(&mut *buffer)
            .ioport_in8(self.base + Self::RECEIVE_BUFFER)
            .ok()?;
        if status & Self::DATA_ERRORS != 0 {
            return None;
        }
        Some(data)
    }
}

const GRANULE_BYTES: usize = 4096;

/// The virtio-mmio registers that identify a transport.
///
/// Offsets from the virtio 1.x specification's MMIO layout. Only the
/// identifying quarter is named here; queue and status registers belong to the
/// driver that owns the device.
pub mod mmio {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;

    /// `"virt"` little-endian, the value a present transport reports.
    pub const MAGIC: u32 = 0x7472_6976;
    /// Device id 0 means the slot exists but carries no device, which is what
    /// most of qemu-arm-virt's thirty-two transports report.
    pub const DEVICE_ID_NONE: u32 = 0;
    pub const DEVICE_ID_BLOCK: u32 = 2;
}

/// One probed virtio-mmio transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioMmio {
    pub paddr: usize,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
}

impl VirtioMmio {
    /// Identify the transport mapped at `region`, or `None` if there is none.
    ///
    /// A slot whose magic does not match holds no virtio transport at all; a
    /// slot reporting device id 0 is a transport with nothing attached. Both
    /// are ordinary results on this platform rather than errors — QEMU declares
    /// thirty-two transports whether or not a disk is attached to any of them.
    pub fn probe(region: &DeviceRegion, offset: usize) -> Option<Self> {
        if region.read32(offset + mmio::MAGIC_VALUE)? != mmio::MAGIC {
            return None;
        }
        let device_id = region.read32(offset + mmio::DEVICE_ID)?;
        if device_id == mmio::DEVICE_ID_NONE {
            return None;
        }
        Some(Self {
            paddr: region.physical_address() + offset,
            version: region.read32(offset + mmio::VERSION)?,
            device_id,
            vendor_id: region.read32(offset + mmio::VENDOR_ID)?,
        })
    }
}

/// A bound device interrupt (P5.4.2b).
///
/// `platform_timer`'s acquisition pattern, generalised: allocate a
/// notification, mint a badged sender-only copy, bind that copy to an IRQ
/// handler, and keep the unbadged original to wait on. Signals arrive with the
/// badge, so a wait can tell which source fired.
///
/// The badge is the caller's, not this module's, so several device interrupts
/// can share one wait without becoming indistinguishable.
pub struct DeviceIrq {
    irq_handler: sel4::cap::IrqHandler,
    notification: sel4::cap::Notification,
    signal: sel4::cap::Notification,
    irq: sel4::Word,
}

impl DeviceIrq {
    /// Claim `irq`, bind a badged notification, and return the live binding.
    ///
    /// `level_triggered` matters: a virtio-mmio device holds its line asserted
    /// until the driver writes `InterruptACK`, so acknowledging the handler
    /// before clearing the device condition re-fires immediately. That ordering
    /// is the driver's to get right — [`Self::acknowledge`] is the second half
    /// of it and must be called last.
    pub fn acquire(
        allocator: &mut ObjectAllocator,
        irq: sel4::Word,
        badge: sel4::Word,
        level_triggered: bool,
    ) -> Result<Self, DeviceError> {
        let notification_slot = allocator
            .allocate_fixed::<sel4::cap_type::Notification>()
            .map_err(DeviceError::Allocate)?;
        let signal_slot = allocator
            .reserve_slot::<sel4::cap_type::Notification>()
            .map_err(DeviceError::Allocate)?;
        let irq_handler_slot = allocator
            .reserve_slot::<sel4::cap_type::IrqHandler>()
            .map_err(DeviceError::Allocate)?;
        let root_cnode = sel4::init_thread::slot::CNODE.cap();
        root_cnode
            .absolute_cptr(signal_slot.cptr())
            .mint(
                &root_cnode.absolute_cptr(notification_slot.cptr()),
                sel4::CapRightsBuilder::none().write(true).build(),
                badge,
            )
            .map_err(DeviceError::Irq)?;
        crate::irq_control::acquire_handler(
            irq,
            level_triggered,
            &root_cnode.absolute_cptr(irq_handler_slot.cptr()),
        )
        .map_err(DeviceError::Irq)?;
        irq_handler_slot
            .cap()
            .irq_handler_set_notification(signal_slot.cap())
            .map_err(DeviceError::Irq)?;
        Ok(Self {
            irq_handler: irq_handler_slot.cap(),
            notification: notification_slot.cap(),
            signal: signal_slot.cap(),
            irq,
        })
    }

    pub fn irq(&self) -> sel4::Word {
        self.irq
    }

    /// The capability to wait or poll on. Full rights, but signalling only ever
    /// happens through the badged copy the kernel holds.
    pub fn notification(&self) -> sel4::cap::Notification {
        self.notification
    }

    /// Non-blocking check for a pending signal, returning the badge.
    pub fn poll(&self) -> Option<sel4::Word> {
        let (_, badge) = self.notification.poll();
        (badge != 0).then_some(badge)
    }

    /// Re-arm the interrupt. Call **after** the device's own condition is
    /// cleared, or a level-triggered line fires again immediately.
    pub fn acknowledge(&self) -> Result<(), DeviceError> {
        self.irq_handler.irq_handler_ack().map_err(DeviceError::Irq)
    }

    /// Clear the kernel binding and delete every root capability that kept this
    /// interrupt live. Deletion and clear are safe to repeat, which lets a
    /// higher-level deterministic teardown retry after a later action failed.
    pub fn release(&self, allocator: &mut ObjectAllocator) -> Result<(), DeviceError> {
        self.irq_handler
            .irq_handler_clear()
            .map_err(DeviceError::Irq)?;
        let root = sel4::init_thread::slot::CNODE.cap();
        for cap in [
            self.signal.bits(),
            self.notification.bits(),
            self.irq_handler.bits(),
        ] {
            root.absolute_cptr(sel4::cap::Unspecified::from_bits(cap))
                .delete()
                .map_err(DeviceError::Irq)?;
        }
        allocator.release_slot(self.signal.bits() as usize);
        allocator.release_slot(self.notification.bits() as usize);
        allocator.release_slot(self.irq_handler.bits() as usize);
        Ok(())
    }
}

/// One page of ordinary RAM the root can name to a device (P5.4.2b).
///
/// A virtqueue is memory both sides read: the driver writes descriptors and the
/// device follows them, so every address in them must be the *guest-physical*
/// one. seL4 gives no way to ask a frame capability where it lives, which is
/// why [`ObjectAllocator`] records the physical base of what it retypes — this
/// type is the join between that record and a mapping the root can write.
///
/// Mapped non-cacheably for the same reason a register bank is: the device
/// reads this memory without going through the CPU's caches, so a descriptor
/// sitting in a dirty line is a descriptor the device does not see. Correct on
/// qemu-arm-virt, whose virtio transports are declared `dma-coherent`; a
/// platform needing explicit maintenance would need barriers here too.
pub struct DmaPage {
    base: usize,
    paddr: usize,
    child_vspace: Option<usize>,
    #[allow(dead_code)]
    frame: sel4::cap::Granule,
}

impl DmaPage {
    /// Retype one granule of ordinary RAM and map it at `base`.
    ///
    /// `base` must be a granule-aligned root-image address already released by
    /// [`crate::child_vspace::ScratchPage::claim`], as for [`DeviceRegion`].
    pub fn allocate(
        allocator: &mut ObjectAllocator,
        vspace: sel4::cap::VSpace,
        base: usize,
    ) -> Result<Self, DeviceError> {
        let slot = allocator
            .allocate_fixed::<sel4::cap_type::Granule>()
            .map_err(DeviceError::Allocate)?;
        let paddr = allocator
            .physical_address_of(slot.index())
            .ok_or(DeviceError::Allocate(AllocError::NoKernelUntyped))?;
        let frame = slot.cap();
        frame
            .frame_map(
                vspace,
                base,
                sel4::CapRights::read_write(),
                uncached_attributes(),
            )
            .map_err(DeviceError::Map)?;
        // Zeroed: a virtqueue's available and used rings are read by the device
        // before the driver writes every field, and untyped memory retyped into
        // a frame is not guaranteed to be anything in particular.
        //
        // SAFETY: `base` names one granule mapped read-write above, and no
        // other reference to it exists — the frame was retyped in this call.
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, GRANULE_BYTES) };
        Ok(Self {
            base,
            paddr,
            frame,
            child_vspace: None,
        })
    }

    /// Retype one DMA page directly into a child VSpace. The shared-buffer
    /// mapping mechanism supplies missing intermediate translation tables.
    pub fn allocate_child(
        allocator: &mut ObjectAllocator,
        vspace: sel4::cap::VSpace,
        base: usize,
    ) -> Result<Self, DeviceError> {
        use crate::shared_buffer::SharedBufferAdapter;

        let slot = allocator
            .allocate_fixed::<sel4::cap_type::Granule>()
            .map_err(DeviceError::Allocate)?;
        let paddr = allocator
            .physical_address_of(slot.index())
            .ok_or(DeviceError::Allocate(AllocError::NoKernelUntyped))?;
        let frame = slot.cap();
        let mut adapter = crate::buffer_adapter::BufferAdapter::new(allocator);
        adapter
            .map_frame(
                crate::shared_buffer::FrameCap(slot.index()),
                crate::shared_buffer::VSpaceCap(vspace.bits() as usize),
                base,
                crate::shared_buffer::MappingRights::ReadWrite,
            )
            .map_err(|_| DeviceError::Map(sel4::Error::FailedLookup))?;
        Ok(Self {
            base,
            paddr,
            frame,
            child_vspace: Some(vspace.bits() as usize),
        })
    }

    /// Map an already-retyped contiguous granule CSlot into a child VSpace.
    pub fn map_child_slot(
        allocator: &mut ObjectAllocator,
        slot: usize,
        vspace: sel4::cap::VSpace,
        base: usize,
    ) -> Result<Self, DeviceError> {
        use crate::shared_buffer::SharedBufferAdapter;

        let paddr = allocator
            .physical_address_of(slot)
            .ok_or(DeviceError::Allocate(AllocError::NoKernelUntyped))?;
        let frame =
            crate::root_cspace::RootSlot::<sel4::cap_type::Granule>::from_address(slot).cap();
        let mut adapter = crate::buffer_adapter::BufferAdapter::new(allocator);
        adapter
            .map_frame(
                crate::shared_buffer::FrameCap(slot),
                crate::shared_buffer::VSpaceCap(vspace.bits() as usize),
                base,
                crate::shared_buffer::MappingRights::ReadWrite,
            )
            .map_err(|_| DeviceError::Map(sel4::Error::FailedLookup))?;
        Ok(Self {
            base,
            paddr,
            frame,
            child_vspace: Some(vspace.bits() as usize),
        })
    }

    /// Guest-physical base, the address a descriptor carries.
    pub fn physical_address(&self) -> usize {
        self.paddr
    }

    /// Virtual base, the address the root writes through.
    pub fn address(&self) -> usize {
        self.base
    }

    /// Mutable bytes for queue construction. The device and root intentionally
    /// write the same bytes.
    ///
    /// # Safety
    ///
    /// The returned slice aliases memory a device may be reading or writing
    /// concurrently through DMA, so it is not an exclusive reference in the way
    /// its type suggests. The caller must only touch bytes the device is not
    /// currently using — in practice, ring entries the device has not been
    /// notified about, or ones it has already completed. The compiler cannot
    /// check that, which is the whole reason this is `unsafe`.
    pub unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `base` names one granule mapped read-write by `allocate` and
        // owned by this value; `&mut self` makes this the only CPU-side view.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, GRANULE_BYTES) }
    }

    /// Tear down a driver-owned DMA page and return its root CSlot. The value
    /// remains available to the caller when an effect fails, so teardown can
    /// retry without losing the capability that names the live mapping.
    pub fn release(&self, allocator: &mut ObjectAllocator) -> Result<(), DeviceError> {
        self.frame.frame_unmap().map_err(DeviceError::Map)?;
        if let Some(vspace) = self.child_vspace {
            allocator
                .release_mapping_page(vspace, self.base)
                .map_err(DeviceError::Allocate)?;
        }
        let slot = self.frame.bits() as usize;
        sel4::init_thread::slot::CNODE
            .cap()
            .absolute_cptr(self.frame)
            .delete()
            .map_err(DeviceError::Map)?;
        allocator.release_slot(slot);
        Ok(())
    }
}

/// Device ordinals admitted by the userspace IO-resource mechanism.
///
/// Two, because the recovery and transfer planes use a source and receiver at
/// once. This bounds raw device authority; only the boot-selector build turns
/// an ordinal into a root-owned block driver.
pub const MAX_IO_DEVICES: usize = 2;

/// Register banks an inventory can hold standing mappings for: the widest
/// platform scan (eight virtio-mmio granules) bounds it, and a declared device
/// occupies one.
pub const MAX_AUTHORITY_REGIONS: usize = 8;

/// One device userspace may be granted: the inventory region holding its
/// registers and the byte offset of its first register within that granule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityDevice {
    pub region: usize,
    pub offset: usize,
}

/// The devices userspace drivers may be granted, with the standing root
/// mappings and interrupt handles behind them. A boot fills it one way only:
/// the platform scan of the virtio-mmio window, or a single region the
/// generation's platform declares. Its device ordinals are the budget's
/// `device` field, so the order they are pushed in is the order a
/// composition names.
pub struct AuthorityInventory {
    regions: [Option<DeviceRegion>; MAX_AUTHORITY_REGIONS],
    devices: [Option<AuthorityDevice>; MAX_IO_DEVICES],
    irqs: [Option<DeviceIrq>; MAX_AUTHORITY_REGIONS],
    len: usize,
}

impl Default for AuthorityInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorityInventory {
    pub const fn new() -> Self {
        Self {
            regions: [const { None }; MAX_AUTHORITY_REGIONS],
            devices: [None; MAX_IO_DEVICES],
            irqs: [const { None }; MAX_AUTHORITY_REGIONS],
            len: 0,
        }
    }
    /// A device the generation declares rather than one the root discovers:
    /// the pre-carved region is device 0 at offset 0, and nothing else is
    /// inventoried, so a budget naming any other ordinal binds no device.
    pub fn declared(region: DeviceRegion) -> Self {
        let mut inventory = Self::new();
        inventory.regions[0] = Some(region);
        inventory.devices[0] = Some(AuthorityDevice {
            region: 0,
            offset: 0,
        });
        inventory.len = 1;
        inventory
    }
    /// Hold `region` at `index`. Refused, returning the region, when the index
    /// is out of range or already holds one: a standing mapping is never
    /// silently replaced.
    pub fn install_region(
        &mut self,
        index: usize,
        region: DeviceRegion,
    ) -> Result<(), DeviceRegion> {
        match self.regions.get_mut(index) {
            Some(slot @ None) => {
                *slot = Some(region);
                Ok(())
            }
            _ => Err(region),
        }
    }
    /// Append a device at the next ordinal. `false` when the ceiling is
    /// reached or the device names a region this inventory does not hold.
    pub fn push_device(&mut self, device: AuthorityDevice) -> bool {
        if self.len >= MAX_IO_DEVICES || self.region(device.region).is_none() {
            return false;
        }
        self.devices[self.len] = Some(device);
        self.len += 1;
        true
    }
    /// The inventoried devices, for the platform to put into its stable order.
    pub fn devices_mut(&mut self) -> &mut [Option<AuthorityDevice>] {
        &mut self.devices[..self.len]
    }
    pub fn device(&self, index: usize) -> Option<AuthorityDevice> {
        self.devices.get(index).copied().flatten()
    }
    pub fn region(&self, index: usize) -> Option<&DeviceRegion> {
        self.regions.get(index)?.as_ref()
    }
    pub fn region_mut(&mut self, index: usize) -> Option<&mut DeviceRegion> {
        self.regions.get_mut(index)?.as_mut()
    }
    pub fn unmap_region_at(&mut self, base: usize) -> Result<(), DeviceError> {
        self.regions
            .iter_mut()
            .flatten()
            .find(|region| region.mapped_base() == base)
            .ok_or(DeviceError::NoRegion)?
            .unmap()
    }
    pub fn take_irq(&mut self, index: usize) -> Option<DeviceIrq> {
        self.irqs.get_mut(index)?.take()
    }
    pub fn irq(&self, index: usize) -> Option<&DeviceIrq> {
        self.irqs.get(index)?.as_ref()
    }
    pub fn put_irq(&mut self, index: usize, irq: DeviceIrq) -> Result<(), DeviceError> {
        let slot = self.irqs.get_mut(index).ok_or(DeviceError::IrqSlot)?;
        if slot.is_some() {
            return Err(DeviceError::IrqSlot);
        }
        *slot = Some(irq);
        Ok(())
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    /// A region that maps nothing: the inventory never dereferences one.
    fn region(paddr: usize) -> DeviceRegion {
        DeviceRegion {
            base: 0x1000,
            paddr,
            frame: sel4::cap::Granule::from_bits(0),
        }
    }

    #[test]
    fn a_declared_region_is_device_zero_at_offset_zero_and_nothing_else() {
        let inventory = AuthorityInventory::declared(region(0x0a00_3000));
        assert_eq!(inventory.len(), 1);
        assert_eq!(
            inventory.device(0),
            Some(AuthorityDevice {
                region: 0,
                offset: 0
            })
        );
        assert_eq!(
            inventory.region(0).map(DeviceRegion::paddr),
            Some(0x0a00_3000)
        );
        assert_eq!(inventory.device(1), None);
        assert!(inventory.region(1).is_none());
        assert!(inventory.irq(0).is_none());
    }

    #[test]
    fn devices_are_pushed_in_order_against_held_regions_and_the_ceiling() {
        let mut inventory = AuthorityInventory::new();
        assert!(inventory.is_empty());
        assert!(inventory.install_region(0, region(0xa00_0000)).is_ok());
        assert!(inventory.install_region(0, region(0xa00_1000)).is_err());
        assert!(
            inventory
                .install_region(MAX_AUTHORITY_REGIONS, region(0))
                .is_err()
        );
        assert!(!inventory.push_device(AuthorityDevice {
            region: 1,
            offset: 0
        }));
        assert!(inventory.push_device(AuthorityDevice {
            region: 0,
            offset: 0x200
        }));
        assert!(inventory.push_device(AuthorityDevice {
            region: 0,
            offset: 0
        }));
        assert!(!inventory.push_device(AuthorityDevice {
            region: 0,
            offset: 0x400
        }));
        assert_eq!(inventory.len(), MAX_IO_DEVICES);
        inventory
            .devices_mut()
            .sort_unstable_by_key(|entry| entry.map_or(0, |d| d.offset));
        assert_eq!(inventory.device(0).map(|d| d.offset), Some(0));
        assert_eq!(inventory.device(1).map(|d| d.offset), Some(0x200));
    }
}

#[cfg(slime_boot_selector)]
pub const MAX_BLOCK_DEVICES: usize = MAX_IO_DEVICES;

#[cfg(slime_boot_selector)]
/// The brought-up devices.
pub struct BlockDevices {
    devices: [Option<crate::boot_selector_block::VirtioBlock>; MAX_BLOCK_DEVICES],
    len: usize,
}

#[cfg(slime_boot_selector)]
impl Default for BlockDevices {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(slime_boot_selector)]
impl BlockDevices {
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_BLOCK_DEVICES],
            len: 0,
        }
    }

    pub fn push(&mut self, device: crate::boot_selector_block::VirtioBlock) {
        if self.len < MAX_BLOCK_DEVICES {
            self.devices[self.len] = Some(device);
            self.len += 1;
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut crate::boot_selector_block::VirtioBlock> {
        self.devices.get_mut(index)?.as_mut()
    }
}
