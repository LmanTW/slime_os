use super::*;

use crate::io_resource::{
    AdapterAction, AdapterError, DeviceId, DmaDirection, DriverEpoch, DriverId, IoResourceAdapter,
    IrqHandle, IrqSourceId, LeaseId, MAX_DMA_MAPPINGS, MmioAccess, MmioIsolation, MmioRegionId,
    ResourceError, ResourceTable, mediated_mmio_offset,
};

#[derive(Clone, Copy)]
struct QueueRecord {
    first: usize,
    pages: usize,
}

pub(crate) struct IoResourceService {
    pub table: ResourceTable,
    next_epoch: [u64; generation::MAX_ADMITTED_INSTANCES],
    dma_pages: [Option<device::DmaPage>; MAX_DMA_MAPPINGS],
    queues: [Option<QueueRecord>; MAX_DMA_MAPPINGS],
}

impl IoResourceService {
    pub const fn new() -> Self {
        Self {
            table: ResourceTable::new(),
            next_epoch: [1; generation::MAX_ADMITTED_INSTANCES],
            dma_pages: [const { None }; MAX_DMA_MAPPINGS],
            queues: [None; MAX_DMA_MAPPINGS],
        }
    }
}

struct Sel4IoAdapter<'a> {
    inventory: &'a mut platform::AuthorityInventory,
    allocator: &'a mut ObjectAllocator,
    caller_vspace: sel4::cap::VSpace,
    requested_base: usize,
    granted_mmio_bytes: u32,
    dma_pages: &'a mut [Option<device::DmaPage>; MAX_DMA_MAPPINGS],
    queues: &'a mut [Option<QueueRecord>; MAX_DMA_MAPPINGS],
    loan_frames: Option<shared_buffer::LoanFrames>,
}

impl Sel4IoAdapter<'_> {
    /// Zero-based inventory index of a one-based `DeviceId`.
    fn index(&self, device: DeviceId) -> Result<usize, AdapterError> {
        let index = device.0.checked_sub(1).ok_or(AdapterError::MapFailed)? as usize;
        (index < self.inventory.len())
            .then_some(index)
            .ok_or(AdapterError::MapFailed)
    }
    fn device(&self, device: DeviceId) -> Result<platform::AuthorityDevice, AdapterError> {
        self.inventory
            .device(self.index(device)?)
            .ok_or(AdapterError::MapFailed)
    }
}

impl IoResourceAdapter for Sel4IoAdapter<'_> {
    fn map_mmio(
        &mut self,
        device: DeviceId,
        _: MmioRegionId,
        offset: u32,
        length: u32,
        access: MmioAccess,
    ) -> Result<u64, AdapterError> {
        if offset != 0
            || length as usize != child_vspace::GRANULE_SIZE
            || !self
                .requested_base
                .is_multiple_of(child_vspace::GRANULE_SIZE)
        {
            return Err(AdapterError::MapFailed);
        }
        let descriptor = self.device(device)?;
        self.allocator
            .prepare_mapping_page(self.caller_vspace.bits() as usize, self.requested_base)
            .map_err(|_| AdapterError::MapFailed)?;
        let outcome = (|| {
            crate::buffer_adapter::BufferAdapter::new(self.allocator)
                .ensure_mapping_tables(self.caller_vspace, self.requested_base)
                .map_err(|_| AdapterError::MapFailed)?;
            self.inventory
                .region_mut(descriptor.region)
                .ok_or(AdapterError::MapFailed)?
                .map_child(
                    self.caller_vspace,
                    self.requested_base,
                    matches!(access, MmioAccess::ReadWrite),
                )
                .map_err(|_| AdapterError::MapFailed)
        })();
        if let Err(error) = outcome {
            let _ = self
                .allocator
                .release_mapping_page(self.caller_vspace.bits() as usize, self.requested_base);
            return Err(error);
        }
        Ok(self.requested_base as u64)
    }

    fn read_mmio32(
        &mut self,
        device: DeviceId,
        _: MmioRegionId,
        offset: u32,
    ) -> Result<u32, AdapterError> {
        let descriptor = self.device(device)?;
        let offset = mediated_mmio_offset(self.granted_mmio_bytes, descriptor.offset, offset)
            .ok_or(AdapterError::MapFailed)?;
        self.inventory
            .region(descriptor.region)
            .and_then(|region| region.read32(offset))
            .ok_or(AdapterError::MapFailed)
    }

    fn write_mmio32(
        &mut self,
        device: DeviceId,
        _: MmioRegionId,
        offset: u32,
        value: u32,
    ) -> Result<(), AdapterError> {
        let descriptor = self.device(device)?;
        let offset = mediated_mmio_offset(self.granted_mmio_bytes, descriptor.offset, offset)
            .ok_or(AdapterError::MapFailed)?;
        self.inventory
            .region(descriptor.region)
            .filter(|region| region.write32(offset, value))
            .map(|_| ())
            .ok_or(AdapterError::MapFailed)
    }

    /// Bind this device's interrupt.
    ///
    /// Keyed by the device ordinal, not by the granule it lives in (B84). QEMU
    /// places two virtio disks at `0xa003e00` and `0xa003c00` — the same 4 KiB
    /// granule — so a granule-keyed slot makes the second device's bind fail as
    /// "already bound" while actually holding the first device's interrupt. The
    /// SPI still comes from the transport's own physical address, so two
    /// devices in one granule get two different interrupts.
    fn bind_irq(&mut self, device: DeviceId, _: IrqSourceId) -> Result<(), AdapterError> {
        let index = self.index(device)?;
        let descriptor = self.device(device)?;
        if self.inventory.irq(index).is_some() {
            return Err(AdapterError::IrqFailed);
        }
        let paddr = self
            .inventory
            .region(descriptor.region)
            .ok_or(AdapterError::IrqFailed)?
            .physical_address()
            + descriptor.offset;
        let irq = virtio_irq(paddr);
        let binding = device::DeviceIrq::acquire(self.allocator, irq, VIRTIO_IRQ_BADGE, true)
            .map_err(|_| AdapterError::IrqFailed)?;
        self.inventory
            .put_irq(index, binding)
            .map_err(|_| AdapterError::IrqFailed)
    }

    /// Acknowledge through the same device-keyed slot `bind_irq` filled.
    ///
    /// `install_driver` grants source `device + 1`, so the source ordinal and
    /// the device ordinal coincide; this converts explicitly rather than
    /// relying on that.
    fn ack_irq(&mut self, source: IrqSourceId) -> Result<(), AdapterError> {
        let index = self.index(DeviceId(source.0))?;
        self.inventory
            .irq(index)
            .ok_or(AdapterError::IrqFailed)?
            .acknowledge()
            .map_err(|_| AdapterError::IrqFailed)
    }

    fn create_dma_mapping(
        &mut self,
        _: DeviceId,
        _: LeaseId,
        pages: u32,
        direction: DmaDirection,
    ) -> Result<(u64, u64), AdapterError> {
        let frames = self.loan_frames.ok_or(AdapterError::DmaFailed)?;
        let print =
            super::diagnostic_once::payload_dma(matches!(direction, DmaDirection::DeviceRead));
        if print {
            crate::diagnostic_println!(
                "SLIME_IO payload dma pages={} frames={} writable={} direction={direction:?}",
                pages,
                frames.len(),
                frames.writable()
            );
        }
        if frames.len() != pages as usize
            || matches!(direction, DmaDirection::DeviceWrite) && !frames.writable()
        {
            return Err(AdapterError::DmaFailed);
        }
        let mut first = None;
        for index in 0..frames.len() {
            let frame = frames.get(index).ok_or(AdapterError::DmaFailed)?;
            let paddr = self.allocator.physical_address_of(frame.0);
            if print {
                crate::diagnostic_println!(
                    "SLIME_IO payload frame index={index} slot={} paddr={paddr:?}",
                    frame.0
                );
            }
            let paddr = paddr.ok_or(AdapterError::DmaFailed)?;
            if let Some(base) = first {
                if paddr != base + index * shared_buffer::PAGE_SIZE {
                    return Err(AdapterError::DmaFailed);
                }
            } else {
                first = Some(paddr);
            }
        }
        let iova = first.ok_or(AdapterError::DmaFailed)? as u64;
        Ok((u64::MAX, iova))
    }

    fn create_device_queue(&mut self, _: DeviceId, pages: u32) -> Result<(u64, u64), AdapterError> {
        let pages = usize::try_from(pages).map_err(|_| AdapterError::DmaFailed)?;
        if pages == 0
            || !self
                .requested_base
                .is_multiple_of(child_vspace::GRANULE_SIZE)
        {
            return Err(AdapterError::DmaFailed);
        }
        let first = (0..=self.dma_pages.len().saturating_sub(pages))
            .find(|start| {
                self.dma_pages[*start..*start + pages]
                    .iter()
                    .all(Option::is_none)
            })
            .ok_or(AdapterError::DmaFailed)?;
        let queue = self
            .queues
            .iter()
            .position(Option::is_none)
            .ok_or(AdapterError::DmaFailed)?;
        let (first_slot, iova) =
            self.allocator
                .allocate_contiguous_granules(pages)
                .map_err(|error| {
                    crate::diagnostic_println!(
                        "SLIME_IO queue contiguous allocation failed pages={pages} error={error:?}"
                    );
                    AdapterError::DmaFailed
                })?;
        let mut allocated = 0;
        for index in 0..pages {
            match device::DmaPage::map_child_slot(
                self.allocator,
                first_slot + index,
                self.caller_vspace,
                self.requested_base + index * child_vspace::GRANULE_SIZE,
            ) {
                Ok(page) => {
                    self.dma_pages[first + index] = Some(page);
                    allocated += 1;
                }
                Err(error) => {
                    crate::diagnostic_println!(
                        "SLIME_IO queue map failed index={index} error={error:?}"
                    );
                    for rollback in 0..allocated {
                        if let Some(page) = self.dma_pages[first + rollback].take() {
                            let _ = page.release(self.allocator);
                        }
                    }
                    return Err(AdapterError::DmaFailed);
                }
            }
        }
        self.queues[queue] = Some(QueueRecord { first, pages });
        Ok(((queue + 1) as u64, iova as u64))
    }

    fn perform(&mut self, action: AdapterAction) -> Result<(), AdapterError> {
        match action {
            AdapterAction::UnmapMmio { token } => {
                let base = usize::try_from(token).map_err(|_| AdapterError::TeardownFailed)?;
                if self
                    .allocator
                    .mapping_page_tracked(self.caller_vspace.bits() as usize, base)
                {
                    self.inventory
                        .unmap_region_at(base)
                        .map_err(|_| AdapterError::TeardownFailed)?;
                }
                self.allocator
                    .release_mapping_page(self.caller_vspace.bits() as usize, base)
                    .map_err(|_| AdapterError::TeardownFailed)?;
            }
            AdapterAction::UnbindIrq { source } => {
                // The same device-keyed slot `bind_irq` filled, not the granule
                // it lives in (B84): releasing by granule would free the other
                // device's interrupt when two share a page.
                let index = self
                    .index(DeviceId(source.0))
                    .map_err(|_| AdapterError::TeardownFailed)?;
                let Some(irq) = self.inventory.irq(index) else {
                    return Ok(());
                };
                irq.release(self.allocator)
                    .map_err(|_| AdapterError::TeardownFailed)?;
                self.inventory.take_irq(index);
            }
            AdapterAction::DestroyDma { token } => {
                if token == u64::MAX {
                    return Ok(());
                }
                let slot = token
                    .checked_sub(1)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or(AdapterError::TeardownFailed)?;
                let Some(record) = self.queues.get(slot).copied().flatten() else {
                    return Ok(());
                };
                for index in 0..record.pages {
                    if let Some(page) = self.dma_pages[record.first + index].as_ref() {
                        page.release(self.allocator)
                            .map_err(|_| AdapterError::TeardownFailed)?;
                        self.dma_pages[record.first + index] = None;
                    }
                }
                self.queues[slot] = None;
            }
            AdapterAction::SettleRequest { .. } => {}
        }
        Ok(())
    }
}

fn denied() -> Response {
    Response::error(IpcError::BadCapability)
}
fn invalid() -> Response {
    Response::error(IpcError::InvalidOperation)
}
fn mapped<T>(outcome: Result<T, ResourceError>, ok: impl FnOnce(T) -> Response) -> Response {
    match outcome {
        Ok(value) => ok(value),
        Err(_) => invalid(),
    }
}

/// Refuse an I/O mapping whose caller-chosen destination falls inside that
/// caller's own private reservation.
///
/// MMIO and driver-owned queue pages are the two I/O operations that take a
/// virtual base from the component and map into that component's VSpace, so
/// they are subject to the same destination rule as an owned buffer or a loan.
/// The reservation is excluded whole: an authorized maximum reserves no
/// physical page, so the kernel finds nothing to collide with in the unbacked
/// part of the window and the mapping would otherwise succeed there and take
/// address space the holder is entitled to grow into.
///
/// The check belongs here rather than in `DeviceRegion`, `DmaPage` or
/// `BufferAdapter`: those map into a VSpace capability and hold no task record,
/// and the same numeric address is a legitimate destination in every other
/// component. This dispatcher is the one place that has already resolved both
/// the authenticated caller and its requested destination.
fn admit_io_destination(
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
    base: usize,
    length: usize,
) -> Result<(), Response> {
    let Some(record) = tasks.get(task) else {
        return Err(denied());
    };
    super::capability::admit_mapping_destination(record, base, length)
}

/// Install one driver instance's declared hardware budget, bound to the exact
/// transport its generation names.
///
/// The device comes from the budget record rather than from the instance's
/// grants (B84). A plane with two disks declares one driver executable twice,
/// and the root gives every non-`block` typed grant in an instance a single
/// positional index — so the grants of two instances are indistinguishable.
/// This record is already keyed by authenticated instance identity, and one
/// number here names the device for that instance's `device`, `mmioRegion`,
/// `interruptSource`, and `dmaAccount` authority at once, so the four cannot
/// disagree about which transport they mean.
pub(crate) fn install_driver(
    service: &mut IoResourceService,
    driver: DriverId,
    instance: usize,
    quota: boot_contracts::io_resource::DriverQuota,
    shared_granule: bool,
) -> Result<DriverEpoch, ResourceError> {
    // One-based throughout the resource table, where zero means "no device":
    // `declare_quota` refuses `DeviceId(0)`, and `Sel4IoAdapter::device`
    // subtracts one to index the inventory.
    let device = DeviceId(u64::from(quota.device) + 1);
    let region = MmioRegionId(u64::from(quota.device) + 1);
    let source = IrqSourceId(u64::from(quota.device) + 1);
    let epoch = service.table.declare_quota_at_epoch(
        driver,
        device,
        crate::io_resource::DriverQuota {
            mmio_bytes: quota.mmio_bytes,
            mmio_mappings: quota.mmio_mappings,
            dma_pages: quota.dma_pages,
            dma_mappings: quota.dma_mappings,
            irq_sources: quota.irq_sources,
            outstanding_requests: quota.outstanding_requests,
            buffer_loans: quota.buffer_loans,
        },
        DriverEpoch(service.next_epoch[instance]),
    )?;
    service.table.grant_mmio_region(
        driver,
        device,
        region,
        if shared_granule {
            VIRTIO_MMIO_STRIDE as u32
        } else {
            child_vspace::GRANULE_SIZE as u32
        },
        MmioAccess::ReadWrite,
        if shared_granule {
            MmioIsolation::SharedGranule
        } else {
            MmioIsolation::PageExclusive
        },
    )?;
    service.table.grant_irq_source(driver, device, source)?;
    service.next_epoch[instance] = epoch.0;
    Ok(epoch)
}

pub(super) fn reclaim_driver(
    service: &mut IoResourceService,
    inventory: &mut platform::AuthorityInventory,
    allocator: &mut ObjectAllocator,
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
) -> Result<(), ResourceError> {
    let driver = DriverId(u64::from(task.0));
    let instance = tasks
        .get(task)
        .and_then(|task| task.instance)
        .ok_or(ResourceError::NoQuota)?;
    let before = service.table.occupancy(driver);
    if service.table.epoch(driver).is_none() {
        return Ok(());
    }
    let caller_vspace = tasks
        .get(task)
        .map(|task| task.vspace.vspace)
        .unwrap_or(sel4::cap::VSpace::from_bits(0));
    let mut adapter = Sel4IoAdapter {
        inventory,
        allocator,
        caller_vspace,
        requested_base: 0,
        granted_mmio_bytes: 0,
        dma_pages: &mut service.dma_pages,
        queues: &mut service.queues,
        loan_frames: None,
    };
    let (actions, fresh) = service.table.reclaim_driver(&mut adapter, driver)?;
    service.next_epoch[instance] = fresh.0;
    let after = service.table.occupancy(driver);
    crate::diagnostic_println!(
        "SLIME_IO reclaim task={} pre_mmio_bytes={} pre_mmio_mappings={} pre_irq_sources={} pre_dma_pages={} pre_dma_mappings={} pre_requests={} reclaimed_mmio_bytes={} reclaimed_mmio_mappings={} reclaimed_irq_sources={} reclaimed_dma_pages={} reclaimed_dma_mappings={} settled_requests={} post_mmio_bytes={} post_mmio_mappings={} post_irq_sources={} post_dma_pages={} post_dma_mappings={} post_requests={} actions={} fresh_epoch={}",
        task.0,
        before.mmio_bytes,
        before.mmio_mappings,
        before.irq_sources,
        before.dma_pages,
        before.dma_mappings,
        before.outstanding_requests,
        before.mmio_bytes.saturating_sub(after.mmio_bytes),
        before.mmio_mappings.saturating_sub(after.mmio_mappings),
        before.irq_sources.saturating_sub(after.irq_sources),
        before.dma_pages.saturating_sub(after.dma_pages),
        before.dma_mappings.saturating_sub(after.dma_mappings),
        before
            .outstanding_requests
            .saturating_sub(after.outstanding_requests),
        after.mmio_bytes,
        after.mmio_mappings,
        after.irq_sources,
        after.dma_pages,
        after.dma_mappings,
        after.outstanding_requests,
        actions.len(),
        fresh.0,
    );
    Ok(())
}
pub(super) fn revoke_buffer_lease(
    service: &mut IoResourceService,
    inventory: &mut platform::AuthorityInventory,
    allocator: &mut ObjectAllocator,
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
    lease: LeaseId,
) -> Result<(), ResourceError> {
    let caller_vspace = tasks
        .get(task)
        .map(|task| task.vspace.vspace)
        .unwrap_or(sel4::cap::VSpace::from_bits(0));
    let mut adapter = Sel4IoAdapter {
        inventory,
        allocator,
        caller_vspace,
        requested_base: 0,
        granted_mmio_bytes: 0,
        dma_pages: &mut service.dma_pages,
        queues: &mut service.queues,
        loan_frames: None,
    };
    match service.table.revoke_lease(&mut adapter, lease) {
        Ok(_) | Err(ResourceError::LeaseNotLive) => Ok(()),
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn serve_io_resource(
    service: &mut IoResourceService,
    inventory: &mut platform::AuthorityInventory,
    allocator: &mut ObjectAllocator,
    buffers: &mut SharedBufferTable,
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
    driver: DriverId,
    label: sel4::Word,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let Some(table) = tasks.authority(task) else {
        return denied();
    };
    let caller_vspace = tasks
        .get(task)
        .map(|task| task.vspace.vspace)
        .unwrap_or(sel4::cap::VSpace::from_bits(0));
    let mut adapter = Sel4IoAdapter {
        inventory,
        allocator,
        caller_vspace,
        requested_base: words[3] as usize,
        granted_mmio_bytes: 0,
        dma_pages: &mut service.dma_pages,
        queues: &mut service.queues,
        loan_frames: None,
    };
    match label {
        io_resource_labels::BIND => {
            let Some(graph::CapabilityEntry::Device(cap)) = table.get(words[0] as u32) else {
                return denied();
            };
            if !cap
                .rights
                .allows(boot_contracts::generation::RIGHT_MAP_MMIO)
            {
                return denied();
            }
            // The installed device, zero-based, not the capability's positional
            // byte (B84): a driver declared twice carries the same byte in both
            // instances, so returning it would tell each the same thing. The
            // capability is still what authorizes the bind.
            //
            // `checked_sub` rather than `- 1`: the table's `DeviceId` is
            // one-based and `declare_quota` refuses zero, so this cannot
            // currently wrap — but that invariant lives in another module, and
            // a wrap here would answer `u64::MAX` as a device ordinal.
            let Some(device) = service
                .table
                .device(driver)
                .and_then(|device| device.0.checked_sub(1))
            else {
                return denied();
            };
            service.table.epoch(driver).map_or_else(denied, |epoch| {
                Response::success(epoch.0 as i64, device as sel4::Word)
            })
        }
        io_resource_labels::MAP_MMIO => {
            let device_slot = words[0] as u32;
            let region_slot = (words[0] >> 32) as u32;
            let Some(graph::CapabilityEntry::Device(device_cap)) = table.get(device_slot) else {
                return denied();
            };
            let Some(graph::CapabilityEntry::MmioRegion(region_cap)) = table.get(region_slot)
            else {
                return denied();
            };
            if !device_cap
                .rights
                .allows(boot_contracts::generation::RIGHT_MAP_MMIO)
                || !region_cap
                    .rights
                    .allows(boot_contracts::generation::RIGHT_MAP_MMIO)
            {
                return denied();
            }
            let Some(device) = service.table.device(driver) else {
                return denied();
            };
            let region = MmioRegionId(device.0);
            let packed = words[3];
            // At least one granule, because that is what the adapter maps even
            // when a shorter length is requested; a longer request is checked
            // over the range the caller actually asked for.
            let requested = ((packed >> 32) as u32 as usize).max(child_vspace::GRANULE_SIZE);
            if let Err(response) = admit_io_destination(tasks, task, words[2] as usize, requested) {
                return response;
            }
            adapter.requested_base = words[2] as usize;
            mapped(
                service.table.map_mmio(
                    &mut adapter,
                    driver,
                    device,
                    DriverEpoch(words[1]),
                    region,
                    packed as u32,
                    (packed >> 32) as u32,
                    MmioAccess::ReadWrite,
                ),
                |handle| Response::success(handle.id.0 as i64, words[2]),
            )
        }
        io_resource_labels::MMIO_READ32 | io_resource_labels::MMIO_WRITE32 => {
            let Some(graph::CapabilityEntry::Device(device_cap)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            let Some(graph::CapabilityEntry::MmioRegion(region_cap)) = table.get(words[1] as u32)
            else {
                return denied();
            };
            if !device_cap
                .rights
                .allows(boot_contracts::generation::RIGHT_MAP_MMIO)
                || !region_cap
                    .rights
                    .allows(boot_contracts::generation::RIGHT_MAP_MMIO)
            {
                return denied();
            }
            let Some(device) = service.table.device(driver) else {
                return denied();
            };
            let region = MmioRegionId(device.0);
            let Some(granted_bytes) = service.table.mmio_grant_bytes(driver, region) else {
                return denied();
            };
            adapter.granted_mmio_bytes = granted_bytes;
            let epoch = DriverEpoch(words[2]);
            if label == io_resource_labels::MMIO_READ32 {
                mapped(
                    service.table.read_mmio32(
                        &mut adapter,
                        driver,
                        device,
                        epoch,
                        region,
                        words[3] as u32,
                    ),
                    |value| Response::success(i64::from(value), 0),
                )
            } else {
                let packed = words[3];
                mapped(
                    service.table.write_mmio32(
                        &mut adapter,
                        driver,
                        device,
                        epoch,
                        region,
                        packed as u32,
                        (packed >> 32) as u32,
                    ),
                    |_| Response::success(0, 0),
                )
            }
        }
        io_resource_labels::QUEUE_MAP => {
            let Some(graph::CapabilityEntry::DmaAccount(account)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            if !account
                .rights
                .allows(boot_contracts::generation::RIGHT_DMA_PIN)
            {
                return denied();
            }
            let epoch = DriverEpoch(words[2]);
            let Some(device) = service.table.device(driver) else {
                return denied();
            };
            // The whole requested span, not just its base: the queue is mapped
            // page by page, so a base below the window can still walk into it.
            // An overflowing page count is left to the adapter, which refuses
            // it as a bad request like every other unsatisfiable size.
            if let Some(length) = (words[1] as u32 as usize).checked_mul(child_vspace::GRANULE_SIZE)
                && let Err(response) = admit_io_destination(tasks, task, words[3] as usize, length)
            {
                return response;
            }
            match service.table.map_device_queue(
                &mut adapter,
                driver,
                device,
                epoch,
                words[1] as u32,
            ) {
                Ok(handle) => {
                    Response::success(handle.id.0 as i64, handle.iova().value() as sel4::Word)
                }
                Err(error) => {
                    crate::diagnostic_println!(
                        "SLIME_IO queue map refused task={} epoch={} base={:#x} pages={} error={error:?}",
                        task.0,
                        epoch.0,
                        words[3],
                        words[1]
                    );
                    invalid()
                }
            }
        }
        io_resource_labels::DMA_MAP => {
            let Some(graph::CapabilityEntry::DmaAccount(account)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            let Some(graph::CapabilityEntry::Loan(loan_cap)) = table.get(words[1] as u32) else {
                return denied();
            };
            if !account
                .rights
                .allows(boot_contracts::generation::RIGHT_DMA_PIN)
            {
                return denied();
            }
            let direction = match words[2] {
                1 => DmaDirection::DeviceRead,
                2 => DmaDirection::DeviceWrite,
                _ => return invalid(),
            };
            let frames = match buffers.loan_frames(HolderId(u64::from(task.0)), loan_cap.handle) {
                Ok(frames)
                    if !matches!(direction, DmaDirection::DeviceWrite) || frames.writable() =>
                {
                    frames
                }
                _ => return invalid(),
            };
            let epoch = DriverEpoch(words[3]);
            let Some(device) = service.table.device(driver) else {
                return denied();
            };
            if service
                .table
                .declare_lease(
                    driver,
                    epoch,
                    LeaseId(loan_cap.handle.id.0),
                    frames.len() as u32,
                )
                .is_err()
            {
                return invalid();
            }
            adapter.loan_frames = Some(frames);
            mapped(
                service.table.create_dma_mapping(
                    &mut adapter,
                    driver,
                    device,
                    epoch,
                    LeaseId(loan_cap.handle.id.0),
                    direction,
                ),
                |handle| Response::success(handle.id.0 as i64, handle.iova().value() as sel4::Word),
            )
        }
        io_resource_labels::DMA_RELEASE => {
            let Some(graph::CapabilityEntry::DmaAccount(account)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            if !account
                .rights
                .allows(boot_contracts::generation::RIGHT_DMA_RELEASE)
            {
                return denied();
            }
            mapped(
                service.table.destroy_dma_mapping_id(
                    &mut adapter,
                    driver,
                    DriverEpoch(words[2]),
                    crate::io_resource::DmaMappingId(words[1]),
                ),
                |_| Response::success(0, 0),
            )
        }
        io_resource_labels::REQUEST_BEGIN => {
            let Some(graph::CapabilityEntry::DmaAccount(account)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            if !account
                .rights
                .allows(boot_contracts::generation::RIGHT_DMA_PIN)
            {
                return denied();
            }
            mapped(
                service.table.begin_request(
                    driver,
                    DriverEpoch(words[3]),
                    crate::io_resource::RequestId(words[2]),
                    crate::io_resource::DmaMappingId(words[1]),
                ),
                |_| Response::success(0, 0),
            )
        }
        io_resource_labels::REQUEST_SETTLE => {
            let Some(graph::CapabilityEntry::DmaAccount(account)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            if !account
                .rights
                .allows(boot_contracts::generation::RIGHT_DMA_RELEASE)
            {
                return denied();
            }
            mapped(
                service.table.settle_request_id(
                    driver,
                    DriverEpoch(words[3]),
                    crate::io_resource::DmaMappingId(words[1]),
                    crate::io_resource::RequestId(words[2]),
                ),
                |_| Response::success(0, 0),
            )
        }
        io_resource_labels::IRQ_ACK => {
            let Some(graph::CapabilityEntry::InterruptSource(cap)) = table.get(words[0] as u32)
            else {
                return denied();
            };
            if !cap.rights.allows(boot_contracts::generation::RIGHT_IRQ_ACK) {
                return denied();
            }
            let epoch = DriverEpoch(words[1]);
            let Some(device) = service.table.device(driver) else {
                return denied();
            };
            let source = IrqSourceId(device.0);
            if words[2] == 0 {
                return mapped(
                    service
                        .table
                        .bind_irq(&mut adapter, driver, device, epoch, source),
                    |_| Response::success(0, epoch.0 as sel4::Word),
                );
            }
            mapped(
                service.table.ack_irq(
                    &mut adapter,
                    driver,
                    IrqHandle {
                        driver,
                        source,
                        epoch,
                        sequence: words[2],
                    },
                ),
                |_| Response::success(words[2] as i64, epoch.0 as sel4::Word),
            )
        }
        _ => invalid(),
    }
}
