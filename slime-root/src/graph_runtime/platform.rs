use super::*;

/// The inventory is the device module's, so its shape is host-tested; this
/// module owns only how a platform fills it.
pub use crate::device::{AuthorityDevice, AuthorityInventory};

#[cfg(not(slime_boot_selector))]
/// Inventory attached transports without consuming them into the legacy root
/// block driver. This path is selected only after generation admission says
/// userspace hardware authority exists; the two ownership modes are exclusive.
pub fn probe_authority_devices(
    bootinfo: &sel4::BootInfo,
    allocator: &mut ObjectAllocator,
) -> AuthorityInventory {
    // This machine has no virtio-mmio transport window: on QEMU q35 the virtio
    // devices are PCI functions behind an ACPI-described host bridge, and P6
    // deliberately enumerates no PCI (H2 owns that). Returning the empty
    // inventory before claiming a scratch page states that absence, rather
    // than iterating a zero-length range and leaving a reader to work out that
    // the loop body is unreachable.
    #[cfg(target_arch = "x86_64")]
    {
        let _ = (bootinfo, allocator);
        crate::diagnostic_println!(
            "SLIME_ROOT io authority inventory devices=0 mode=userspace transport=absent"
        );
        AuthorityInventory::new()
    }
    #[cfg(not(target_arch = "x86_64"))]
    probe_virtio_mmio_transports(bootinfo, allocator)
}

#[cfg(all(not(slime_boot_selector), not(target_arch = "x86_64")))]
fn probe_virtio_mmio_transports(
    bootinfo: &sel4::BootInfo,
    allocator: &mut ObjectAllocator,
) -> AuthorityInventory {
    let mut inventory = AuthorityInventory::new();
    if allocator.device_untyped_count() == 0 {
        return inventory;
    }
    let scan_base = ptr::addr_of!(DEVICE_PAGE) as usize;
    if ScratchPage::claim(bootinfo, scan_base).is_err() {
        return inventory;
    }
    for granule_index in 0..VIRTIO_MMIO_GRANULES {
        let paddr = VIRTIO_MMIO_BASE + granule_index * GRANULE_SIZE;
        let Ok(mut region) = device::DeviceRegion::map(
            allocator,
            sel4::init_thread::slot::VSPACE.cap(),
            scan_base,
            paddr,
        ) else {
            break;
        };
        let mut attached = [None; VIRTIO_MMIO_SLOTS_PER_GRANULE];
        let mut attached_len = 0;
        for slot in 0..VIRTIO_MMIO_SLOTS_PER_GRANULE {
            if device::VirtioMmio::probe(&region, slot * VIRTIO_MMIO_STRIDE).is_some() {
                attached[attached_len] = Some(slot * VIRTIO_MMIO_STRIDE);
                attached_len += 1;
            }
        }
        if attached_len == 0 {
            let _ = region.unmap();
            continue;
        }
        let standing_base =
            ptr::addr_of!(AUTHORITY_MMIO_PAGES) as usize + granule_index * GRANULE_SIZE;
        if ScratchPage::claim(bootinfo, standing_base).is_err() {
            break;
        }
        let Ok(region) = region.remap(sel4::init_thread::slot::VSPACE.cap(), standing_base) else {
            break;
        };
        if inventory.install_region(granule_index, region).is_err() {
            break;
        }
        for offset in attached.into_iter().flatten() {
            // Past the ordinal ceiling the transport stays mapped but is not a
            // device any budget can name.
            let _ = inventory.push_device(AuthorityDevice {
                region: granule_index,
                offset,
            });
        }
    }
    // QEMU assigns command-line devices from the highest transport down, so
    // reverse physical order is the operator-visible stable device order.
    inventory.devices_mut().sort_unstable_by_key(|entry| {
        core::cmp::Reverse(entry.map_or(0, |d| d.region * GRANULE_SIZE + d.offset))
    });
    crate::diagnostic_println!(
        "SLIME_ROOT io authority inventory devices={} mode=userspace",
        inventory.len()
    );
    inventory
}

#[cfg(slime_boot_selector)]
use crate::boot_selector_block as virtio_blk;
#[cfg(slime_boot_selector)]
use device::{BlockDevices, MAX_BLOCK_DEVICES};

#[cfg(slime_boot_selector)]
/// Report what device authority BootInfo gives this root, and probe the
/// platform's virtio-mmio transports (P5.4.2a).
///
/// Three markers, and each is a distinct claim:
///
/// * `devices untypeds=` — BootInfo named this many device regions. Zero means
///   the platform declares no device memory, which is a fact about the machine
///   rather than a failure.
/// * `device mapped=` — one granule was retyped out of a device untyped and
///   mapped non-cacheably into the root's own VSpace. This is the mechanism
///   P5.4.2's block device needs and the root did not have.
/// * `virtio transport=` — a register read out of that mapping identified a
///   present transport. Absent means the slot exists but nothing is attached,
///   which is what all thirty-two report when QEMU is given no `-drive`.
///
/// Failure is reported and returned from, never fatal: no plane depends on a
/// device yet, and a root that refused to boot without one would break twelve
/// gates to prove nothing.
pub fn probe_devices(bootinfo: &sel4::BootInfo, allocator: &mut ObjectAllocator) -> BlockDevices {
    crate::diagnostic_println!(
        "SLIME_ROOT devices untypeds={}",
        allocator.device_untyped_count(),
    );
    let mut devices = BlockDevices::new();
    if allocator.device_untyped_count() == 0 {
        return devices;
    }
    // SAFETY: the root task is single-threaded and this is the only reference
    // taken to `DEVICE_PAGE`. Its address is granule-aligned by the type's
    // `repr(align(4096))`, and it is claimed exactly once.
    let base = ptr::addr_of!(DEVICE_PAGE) as usize;
    if let Err(error) = ScratchPage::claim(bootinfo, base) {
        crate::diagnostic_println!("SLIME_ROOT device page unavailable: {error:?}");
        return devices;
    }
    // Every transport the platform declares, a granule at a time. One claimed
    // root-image page is enough because the mapping is released between
    // granules — the frame capabilities stay, only the virtual window is
    // reused.
    //
    // Scanning rather than reading one slot: QEMU declares thirty-two identical
    // transports and attaches a device to the *highest* free one, so the
    // occupied slot is a function of how many devices the command line names.
    // A driver will read the FDT to enumerate them; the point here is that the
    // answer comes from register reads rather than from a guess.
    let mut found = 0;
    let mut mapped = 0;
    // Every attached transport, not merely the last one (P5.4.3). M6.7 crosses
    // a persistence boundary, so it needs a source device and a receiver
    // device at once — and a root that kept only the highest-numbered
    // transport could express the milestone's central claim, that an ungranted
    // device is untouched, only by having no second device to touch.
    let mut attached: [Option<device::VirtioMmio>; MAX_BLOCK_DEVICES] = [None; MAX_BLOCK_DEVICES];
    let mut regions: [Option<device::DeviceRegion>; MAX_BLOCK_DEVICES] =
        [const { None }; MAX_BLOCK_DEVICES];
    let mut attached_count = 0;
    // Granules already remapped to a driver's standing window, so a second
    // transport in the same page borrows rather than remaps (B29).
    let mut standing: [Option<(usize, device::MappedGranule)>; MAX_BLOCK_DEVICES] =
        [None; MAX_BLOCK_DEVICES];
    for granule in 0..VIRTIO_MMIO_GRANULES {
        let paddr = VIRTIO_MMIO_BASE + granule * GRANULE_SIZE;
        let mut region = match device::DeviceRegion::map(
            allocator,
            sel4::init_thread::slot::VSPACE.cap(),
            base,
            paddr,
        ) {
            Ok(region) => region,
            Err(error) => {
                crate::diagnostic_println!(
                    "SLIME_ROOT device map failed paddr={paddr:#x} {error:?}"
                );
                return devices;
            }
        };
        mapped += 1;
        for slot in 0..VIRTIO_MMIO_SLOTS_PER_GRANULE {
            let Some(transport) = device::VirtioMmio::probe(&region, slot * VIRTIO_MMIO_STRIDE)
            else {
                continue;
            };
            found += 1;
            crate::diagnostic_println!(
                "SLIME_ROOT virtio transport={:#x} version={} device={} vendor={:#x}",
                transport.paddr,
                transport.version,
                transport.device_id,
                transport.vendor_id,
            );
            if attached_count < MAX_BLOCK_DEVICES {
                attached[attached_count] = Some(transport);
                attached_count += 1;
            } else {
                crate::diagnostic_println!(
                    "SLIME_ROOT virtio transport ignored paddr={:#x} reason=table-full",
                    transport.paddr,
                );
            }
        }
        // Keep the granule holding the attached transport rather than
        // releasing it: seL4's retype is monotonic, so a device untyped's page
        // can be reached exactly once per boot. Unmapping frees the virtual
        // window; the frame capability stays in `region` and is handed to the
        // driver below, which re-maps it at its own standing address.
        // Keep the granule if *any* attached transport lives in it. Several
        // can: the stride is 0x200 and a granule is 0x1000, so eight transports
        // share one page — which is why the region is looked up by address
        // below rather than owned by one transport.
        let holds_attached = attached[..attached_count]
            .iter()
            .any(|entry| entry.is_some_and(|found| found.paddr & !(GRANULE_SIZE - 1) == paddr));
        if holds_attached {
            if let Some(slot) = regions.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(region);
            }
            continue;
        }
        if let Err(error) = region.unmap() {
            crate::diagnostic_println!("SLIME_ROOT device unmap failed paddr={paddr:#x} {error:?}");
            return devices;
        }
    }
    // Bind the interrupt of whichever transport is attached (P5.4.2b).
    //
    // Only for a device that exists: `irq_control_get_trigger` succeeds for any
    // number the platform declares, so acquiring an unattached transport's line
    // would report a binding that can never fire and prove nothing.
    //
    // Level-triggered, because virtio-mmio holds its line asserted until the
    // driver writes `InterruptACK`. Nothing here acknowledges: there is no
    // driver yet to clear the device condition first, and acknowledging before
    // that is exactly the ordering mistake that storms. What this establishes
    // is that the root can *acquire and bind* a device IRQ; servicing one is
    // the transport's.
    // Highest physical address first, which is QEMU command-line order.
    //
    // QEMU fills virtio-mmio slots downward from the highest free one, so the
    // *first* `-device` on the command line lands at the highest address. A
    // generation naming "device 0" therefore means the first disk the operator
    // attached, which is the only ordering an operator can predict.
    attached[..attached_count].sort_unstable_by_key(|entry| {
        core::cmp::Reverse(entry.map_or(0, |transport| transport.paddr))
    });
    for entry in attached.iter().take(attached_count) {
        let Some(transport) = *entry else {
            continue;
        };
        #[cfg(slime_boot_selector)]
        crate::diagnostic_println!(
            "SLIME_ROOT virtio irq polled transport={:#x}",
            transport.paddr,
        );
        let granule = transport.paddr & !(GRANULE_SIZE - 1);
        // A granule another driver already stands in? Then borrow that mapping
        // at this transport's own offset (B29). QEMU packs eight transports
        // into one page, so two attached disks routinely share one, and the
        // frame can be mapped exactly once.
        let block = if let Some(shared) = standing
            .iter()
            .find_map(|entry| entry.filter(|(paddr, _)| *paddr == granule).map(|(_, g)| g))
        {
            bring_up_shared_block(allocator, bootinfo, transport, shared, devices.len())
        } else {
            let region = regions.iter_mut().find_map(|slot| {
                let holds = slot
                    .as_ref()
                    .is_some_and(|region| region.paddr() == granule);
                if holds { slot.take() } else { None }
            });
            let Some(region) = region else {
                crate::diagnostic_println!(
                    "SLIME_ROOT virtio transport skipped paddr={:#x} reason=no-region",
                    transport.paddr,
                );
                continue;
            };
            match bring_up_block(allocator, bootinfo, transport, region, devices.len()) {
                Some((block, borrowed)) => {
                    if let Some(slot) = standing.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some((granule, borrowed));
                    }
                    Some(block)
                }
                None => None,
            }
        };
        if let Some(block) = block {
            devices.push(block);
        }
    }
    crate::diagnostic_println!(
        "SLIME_ROOT virtio probed granules={mapped} slots={} found={found}",
        mapped * VIRTIO_MMIO_SLOTS_PER_GRANULE,
    );
    devices
}

/// Bring up a second transport in a granule another driver already mapped
/// (B29, P5.4.3).
///
/// Everything `bring_up_block` does except the mapping: the frame is already
/// standing at a driver's window, so this allocates only the DMA pages and
/// hands the driver a borrow at its own offset.
#[cfg(slime_boot_selector)]
fn bring_up_shared_block(
    allocator: &mut ObjectAllocator,
    bootinfo: &sel4::BootInfo,
    transport: device::VirtioMmio,
    shared: device::MappedGranule,
    index: usize,
) -> Option<virtio_blk::VirtioBlock> {
    let granule = transport.paddr & !(GRANULE_SIZE - 1);
    let offset = transport.paddr - granule;
    if index >= MAX_BLOCK_DEVICES {
        return None;
    }
    let queue_base = ptr::addr_of!(BOOT_QUEUE_PAGES) as usize + index * GRANULE_SIZE;
    let buffer_base = ptr::addr_of!(BOOT_BUFFER_PAGES) as usize + index * GRANULE_SIZE;
    for address in [queue_base, buffer_base] {
        if let Err(error) = ScratchPage::claim(bootinfo, address) {
            crate::diagnostic_println!("SLIME_ROOT block page unavailable: {error:?}");
            return None;
        }
    }
    let queue = match device::DmaPage::allocate(
        allocator,
        sel4::init_thread::slot::VSPACE.cap(),
        queue_base,
    ) {
        Ok(page) => page,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block queue unavailable: {error:?}");
            return None;
        }
    };
    let buffer = match device::DmaPage::allocate(
        allocator,
        sel4::init_thread::slot::VSPACE.cap(),
        buffer_base,
    ) {
        Ok(page) => page,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block buffer unavailable: {error:?}");
            return None;
        }
    };
    crate::diagnostic_println!(
        "SLIME_ROOT block dma queue={:#x} buffer={:#x}",
        queue.physical_address(),
        buffer.physical_address(),
    );
    let block = match virtio_blk::VirtioBlock::new(shared, offset, queue, buffer) {
        Ok(block) => block,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block bring-up failed {error:?}");
            return None;
        }
    };
    crate::diagnostic_println!(
        "SLIME_ROOT block ready transport={:#x} sectors={}",
        transport.paddr,
        block.capacity_sectors(),
    );
    Some(block)
}

/// Bring up the attached virtio block device and read one sector (P5.4.2b).
///
/// The transport's registers are re-mapped here rather than kept from the
/// probe: the probe unmaps each granule as it scans, so one claimed page can
/// cover all thirty-two slots. This maps the granule the attached transport
/// lives in and keeps it, which is what a live device needs.
///
/// Two DMA pages, both ordinary RAM the allocator can name physically: one for
/// the virtqueue rings, one for the request header, data buffer, and status
/// byte.
///
/// Reading sector 0 is the proof. A driver that negotiated the handshake but
/// never moved a byte would report a capacity and nothing else; a completed
/// read means descriptors the device followed, a buffer it wrote through DMA,
/// and a status byte it set.
#[cfg(slime_boot_selector)]
fn bring_up_block(
    allocator: &mut ObjectAllocator,
    bootinfo: &sel4::BootInfo,
    transport: device::VirtioMmio,
    region: device::DeviceRegion,
    index: usize,
) -> Option<(virtio_blk::VirtioBlock, device::MappedGranule)> {
    let granule = transport.paddr & !(GRANULE_SIZE - 1);
    let offset = transport.paddr - granule;
    if index >= MAX_BLOCK_DEVICES {
        return None;
    }
    // Address arithmetic on the array base rather than indexing the static:
    // indexing reads it, and a mutable static may not be read outside `unsafe`.
    // Each element is exactly one granule, so the offset is exact.
    let base = ptr::addr_of!(BOOT_MMIO_PAGES) as usize + index * GRANULE_SIZE;
    let queue_base = ptr::addr_of!(BOOT_QUEUE_PAGES) as usize + index * GRANULE_SIZE;
    let buffer_base = ptr::addr_of!(BOOT_BUFFER_PAGES) as usize + index * GRANULE_SIZE;
    for address in [base, queue_base, buffer_base] {
        if let Err(error) = ScratchPage::claim(bootinfo, address) {
            crate::diagnostic_println!("SLIME_ROOT block page unavailable: {error:?}");
            return None;
        }
    }
    // The frame the probe already retyped, moved to its own standing address so
    // the scan's shared window stays free.
    let region = match region.remap(sel4::init_thread::slot::VSPACE.cap(), base) {
        Ok(region) => region,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block map failed paddr={granule:#x} {error:?}");
            return None;
        }
    };
    let queue = match device::DmaPage::allocate(
        allocator,
        sel4::init_thread::slot::VSPACE.cap(),
        queue_base,
    ) {
        Ok(page) => page,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block queue unavailable: {error:?}");
            return None;
        }
    };
    let buffer = match device::DmaPage::allocate(
        allocator,
        sel4::init_thread::slot::VSPACE.cap(),
        buffer_base,
    ) {
        Ok(page) => page,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block buffer unavailable: {error:?}");
            return None;
        }
    };
    crate::diagnostic_println!(
        "SLIME_ROOT block dma queue={:#x} buffer={:#x}",
        queue.physical_address(),
        buffer.physical_address(),
    );
    let borrowed = region.granule();
    let block = match virtio_blk::VirtioBlock::new(borrowed, offset, queue, buffer) {
        Ok(block) => block,
        Err(error) => {
            crate::diagnostic_println!("SLIME_ROOT block bring-up failed {error:?}");
            return None;
        }
    };
    crate::diagnostic_println!(
        "SLIME_ROOT block ready transport={:#x} sectors={}",
        transport.paddr,
        block.capacity_sectors(),
    );
    // Bring-up reads. It does not write.
    //
    // It used to: a write/flush/read-back round trip on sector 1 proved the
    // other DMA direction at boot. Sector 1 is the GPT primary header, so on
    // any partitioned disk the root silently destroyed the partition table
    // before userspace ran — the store plane found it as a `bad-magic` primary
    // recovering from the backup on a *freshly built* fixture.
    //
    // The round trip was not worth a device-wide write from boot code that has
    // no idea what the disk holds. `sel4_storage_check` proves both directions
    // and a flush from userspace, on a sector the fixture designates, through a
    // capability — which is where a write belongs.
    //
    // The borrowed handle is returned beside the driver so the probe can give
    // it to another transport in the same granule (B29). `region` falls out of
    // scope here and releases nothing: `DeviceRegion` has no `Drop`, and a
    // bound device stays bound for the boot.
    Some((block, borrowed))
}
