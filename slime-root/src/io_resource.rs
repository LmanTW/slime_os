//! Bounded hardware-resource authority and DMA accounting for userspace drivers.
//!
//! This module is mechanism only. It knows regions, interrupt sources, DMA
//! leases, and charges; it never parses a device descriptor or assigns device
//! policy. Every mutation validates table-held authority before an adapter call,
//! performs the external effect, and commits accounting only after success.
//!
//! Driver-owned queue memory is deliberately a separate operation from payload
//! DMA. A queue is a bidirectional device control structure and carries no
//! client lease; payload mappings remain strictly `DeviceRead` or
//! `DeviceWrite`, with no value that can widen them to both directions.
//! Direct child mapping additionally requires page exclusivity. A region sharing
//! a hardware granule is never rounded outwards; it is accessed through bounded
//! mediated `read32`/`write32`. Each access is bounded to the exact granted
//! subrange before the adapter adds the transport's offset within its granule.

pub const MAX_DRIVERS: usize = 32;
pub const MAX_MMIO_REGIONS: usize = 64;
pub const MAX_MMIO_MAPPINGS: usize = 64;
pub const MAX_DMA_MAPPINGS: usize = 64;
pub const MAX_IRQ_SOURCES: usize = 64;
pub const MAX_LEASES: usize = 128;
pub const MAX_REQUESTS: usize = 128;
pub const MAX_ACTIONS: usize =
    MAX_MMIO_MAPPINGS + MAX_DMA_MAPPINGS + MAX_IRQ_SOURCES + MAX_REQUESTS;
pub const PAGE_SIZE: u32 = 4096;
/// Translate a grant-relative 32-bit MMIO offset into the mapped granule.
/// The grant bound is checked before the device's granule offset is added, so
/// containment follows authority rather than the transport's packing order.
pub fn mediated_mmio_offset(
    granted_bytes: u32,
    device_offset: usize,
    offset: u32,
) -> Option<usize> {
    if offset.checked_add(4).is_none_or(|end| end > granted_bytes) || !offset.is_multiple_of(4) {
        return None;
    }
    device_offset.checked_add(offset as usize)
}

macro_rules! identity {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(pub u64);
    };
}
identity!(DriverId);
identity!(DeviceId);
identity!(MmioRegionId);
identity!(DmaMappingId);
identity!(IrqSourceId);
identity!(DriverEpoch);
identity!(LeaseId);
identity!(RequestId);
identity!(MmioMappingId);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioIsolation {
    PageExclusive,
    SharedGranule,
}
impl MmioAccess {
    const fn permits(self, requested: Self) -> bool {
        matches!(self, Self::ReadWrite) || matches!(requested, Self::ReadOnly)
    }
}

/// DMA direction from the device's viewpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    DeviceRead,
    DeviceWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverQuota {
    pub mmio_bytes: u32,
    pub mmio_mappings: u32,
    pub dma_pages: u32,
    pub dma_mappings: u32,
    pub irq_sources: u32,
    pub outstanding_requests: u32,
    pub buffer_loans: u32,
}

impl DriverQuota {
    pub const DENY: Self = Self {
        mmio_bytes: 0,
        mmio_mappings: 0,
        dma_pages: 0,
        dma_mappings: 0,
        irq_sources: 0,
        outstanding_requests: 0,
        buffer_loans: 0,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverOccupancy {
    pub mmio_bytes: u32,
    pub mmio_mappings: u32,
    pub dma_pages: u32,
    pub dma_mappings: u32,
    pub irq_sources: u32,
    pub outstanding_requests: u32,
    pub buffer_loans: u32,
}

impl DriverOccupancy {
    pub const EMPTY: Self = Self {
        mmio_bytes: 0,
        mmio_mappings: 0,
        dma_pages: 0,
        dma_mappings: 0,
        irq_sources: 0,
        outstanding_requests: 0,
        buffer_loans: 0,
    };
}

/// An opaque driver-visible DMA address. Only [`ResourceTable`] can construct
/// one, and it does so only after authenticating the driver and its DMA account.
/// Shared-buffer possession alone has no API that returns this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Iova(u64);

impl Iova {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioHandle {
    pub id: MmioMappingId,
    pub driver: DriverId,
    pub device: DeviceId,
    pub region: MmioRegionId,
    pub epoch: DriverEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaHandle {
    pub id: DmaMappingId,
    pub driver: DriverId,
    pub epoch: DriverEpoch,
    pub lease: LeaseId,
    pub direction: DmaDirection,
    iova: Iova,
}

impl DmaHandle {
    pub const fn iova(self) -> Iova {
        self.iova
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueDmaHandle {
    pub id: DmaMappingId,
    pub driver: DriverId,
    pub epoch: DriverEpoch,
    pub pages: u32,
    iova: Iova,
}

impl QueueDmaHandle {
    pub const fn iova(self) -> Iova {
        self.iova
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqHandle {
    pub driver: DriverId,
    pub source: IrqSourceId,
    pub epoch: DriverEpoch,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHandle {
    pub driver: DriverId,
    pub id: RequestId,
    pub epoch: DriverEpoch,
    pub mapping: DmaMappingId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    MapFailed,
    IrqFailed,
    DmaFailed,
    TeardownFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterAction {
    /// `device` and `length` name the frames behind `token`: a mapping can
    /// span several granules of one register bank, and teardown unmaps each.
    UnmapMmio {
        token: u64,
        device: DeviceId,
        length: u32,
    },
    UnbindIrq {
        source: IrqSourceId,
    },
    DestroyDma {
        token: u64,
    },
    SettleRequest {
        request: RequestId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionList {
    actions: [Option<AdapterAction>; MAX_ACTIONS],
    len: usize,
}

impl ActionList {
    pub const fn new() -> Self {
        Self {
            actions: [None; MAX_ACTIONS],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn get(&self, index: usize) -> Option<AdapterAction> {
        (index < self.len).then(|| self.actions[index]).flatten()
    }
    pub fn iter(&self) -> impl Iterator<Item = AdapterAction> + '_ {
        self.actions[..self.len].iter().copied().flatten()
    }
    fn push(&mut self, action: AdapterAction) -> Result<(), ResourceError> {
        if self.len == MAX_ACTIONS {
            return Err(ResourceError::TableFull);
        }
        self.actions[self.len] = Some(action);
        self.len += 1;
        Ok(())
    }
}

impl Default for ActionList {
    fn default() -> Self {
        Self::new()
    }
}

/// seL4/MMU/IOMMU effects. Tokens are adapter-private anchors; only the opaque
/// IOVA returned by `create_dma_mapping` crosses to the authenticated driver.
pub trait IoResourceAdapter {
    fn map_mmio(
        &mut self,
        device: DeviceId,
        region: MmioRegionId,
        offset: u32,
        length: u32,
        access: MmioAccess,
    ) -> Result<u64, AdapterError>;
    fn read_mmio32(
        &mut self,
        device: DeviceId,
        region: MmioRegionId,
        offset: u32,
    ) -> Result<u32, AdapterError>;
    fn write_mmio32(
        &mut self,
        device: DeviceId,
        region: MmioRegionId,
        offset: u32,
        value: u32,
    ) -> Result<(), AdapterError>;
    fn bind_irq(&mut self, device: DeviceId, source: IrqSourceId) -> Result<(), AdapterError>;
    fn ack_irq(&mut self, source: IrqSourceId) -> Result<(), AdapterError>;
    fn create_dma_mapping(
        &mut self,
        device: DeviceId,
        lease: LeaseId,
        pages: u32,
        direction: DmaDirection,
    ) -> Result<(u64, u64), AdapterError>;
    fn create_device_queue(
        &mut self,
        device: DeviceId,
        pages: u32,
    ) -> Result<(u64, u64), AdapterError>;
    fn perform(&mut self, action: AdapterAction) -> Result<(), AdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    BadIdentity,
    NoQuota,
    QuotaBusy,
    QuotaExceeded,
    TableFull,
    WrongDriver,
    WrongDevice,
    WrongRegion,
    BadRange,
    BadAccess,
    Duplicate,
    NotFound,
    StaleEpoch,
    LeaseNotLive,
    LeaseBusy,
    MappingBusy,
    WrongSource,
    NoInterrupt,
    DuplicateAck,
    RequestNotLive,
    Adapter(AdapterError),
}

impl From<AdapterError> for ResourceError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Driver {
    id: DriverId,
    device: DeviceId,
    epoch: DriverEpoch,
    quota: DriverQuota,
    occupancy: DriverOccupancy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegionGrant {
    driver: DriverId,
    device: DeviceId,
    id: MmioRegionId,
    bytes: u32,
    access: MmioAccess,
    isolation: MmioIsolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MmioMapping {
    id: MmioMappingId,
    driver: DriverId,
    device: DeviceId,
    epoch: DriverEpoch,
    region: MmioRegionId,
    offset: u32,
    length: u32,
    access: MmioAccess,
    token: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lease {
    driver: DriverId,
    id: LeaseId,
    epoch: DriverEpoch,
    pages: u32,
    mappings: u32,
    requests: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DmaMapping {
    id: DmaMappingId,
    driver: DriverId,
    device: DeviceId,
    epoch: DriverEpoch,
    lease: Option<LeaseId>,
    pages: u32,
    direction: Option<DmaDirection>,
    token: u64,
    iova: Iova,
    requests: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IrqGrant {
    driver: DriverId,
    device: DeviceId,
    source: IrqSourceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IrqBinding {
    driver: DriverId,
    device: DeviceId,
    source: IrqSourceId,
    epoch: DriverEpoch,
    next_sequence: u64,
    pending: Option<u64>,
    last_acked: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Request {
    driver: DriverId,
    id: RequestId,
    epoch: DriverEpoch,
    mapping: DmaMappingId,
}

#[derive(Debug, Clone, Copy)]
struct MmioPlan {
    slot: usize,
    mapping: MmioMapping,
}
#[derive(Debug, Clone, Copy)]
struct DmaPlan {
    slot: usize,
    driver_slot: usize,
    lease_slot: usize,
    mapping: DmaMapping,
}
#[derive(Debug, Clone, Copy)]
struct IrqPlan {
    slot: usize,
    driver_slot: usize,
    binding: IrqBinding,
}

/// Fixed-capacity root-owned state. Device/resource grants are table-held and
/// cannot be widened by caller arguments.
pub struct ResourceTable {
    drivers: [Option<Driver>; MAX_DRIVERS],
    regions: [Option<RegionGrant>; MAX_MMIO_REGIONS],
    irq_grants: [Option<IrqGrant>; MAX_IRQ_SOURCES],
    mmio: [Option<MmioMapping>; MAX_MMIO_MAPPINGS],
    dma: [Option<DmaMapping>; MAX_DMA_MAPPINGS],
    irqs: [Option<IrqBinding>; MAX_IRQ_SOURCES],
    leases: [Option<Lease>; MAX_LEASES],
    requests: [Option<Request>; MAX_REQUESTS],
    next_mmio: u64,
    next_dma: u64,
}

impl ResourceTable {
    pub const fn new() -> Self {
        Self {
            drivers: [None; MAX_DRIVERS],
            regions: [None; MAX_MMIO_REGIONS],
            irq_grants: [None; MAX_IRQ_SOURCES],
            mmio: [None; MAX_MMIO_MAPPINGS],
            dma: [None; MAX_DMA_MAPPINGS],
            irqs: [None; MAX_IRQ_SOURCES],
            leases: [None; MAX_LEASES],
            requests: [None; MAX_REQUESTS],
            next_mmio: 1,
            next_dma: 1,
        }
    }

    pub fn declare_quota(
        &mut self,
        driver: DriverId,
        device: DeviceId,
        quota: DriverQuota,
    ) -> Result<DriverEpoch, ResourceError> {
        if driver.0 == 0 || device.0 == 0 {
            return Err(ResourceError::BadIdentity);
        }
        if let Some(slot) = self.driver_slot(driver) {
            if self.drivers[slot].unwrap().occupancy != DriverOccupancy::EMPTY {
                return Err(ResourceError::QuotaBusy);
            }
            let entry = self.drivers[slot].as_mut().unwrap();
            entry.device = device;
            entry.quota = quota;
            return Ok(entry.epoch);
        }
        let slot = self
            .drivers
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        let epoch = DriverEpoch(1);
        self.drivers[slot] = Some(Driver {
            id: driver,
            device,
            epoch,
            quota,
            occupancy: DriverOccupancy::EMPTY,
        });
        Ok(epoch)
    }

    /// Bind a newly authenticated task identity at an epoch carried across a
    /// supervised predecessor's completed reclamation.
    pub fn declare_quota_at_epoch(
        &mut self,
        driver: DriverId,
        device: DeviceId,
        quota: DriverQuota,
        epoch: DriverEpoch,
    ) -> Result<DriverEpoch, ResourceError> {
        if epoch.0 == 0 {
            return Err(ResourceError::BadIdentity);
        }
        self.declare_quota(driver, device, quota)?;
        let slot = self.driver_slot(driver).ok_or(ResourceError::NoQuota)?;
        self.drivers[slot]
            .as_mut()
            .ok_or(ResourceError::NoQuota)?
            .epoch = epoch;
        Ok(epoch)
    }

    pub fn release_quota(&mut self, driver: DriverId) -> bool {
        let Some(slot) = self.driver_slot(driver) else {
            return false;
        };
        if self.drivers[slot].unwrap().occupancy != DriverOccupancy::EMPTY {
            return false;
        }
        self.drivers[slot] = None;
        self.regions
            .iter_mut()
            .filter(|r| r.is_some_and(|r| r.driver == driver))
            .for_each(|r| *r = None);
        self.irq_grants
            .iter_mut()
            .filter(|g| g.is_some_and(|g| g.driver == driver))
            .for_each(|g| *g = None);
        true
    }

    /// Which device this driver instance was installed against.
    ///
    /// The authenticated answer to "which transport", and the only one: a typed
    /// capability's resource byte is a positional index the root assigns per
    /// instance, so two instances of one driver executable carry identical
    /// bytes (B84). The device is declared in the instance's IO1 budget and
    /// recorded here at install.
    pub fn device(&self, driver: DriverId) -> Option<DeviceId> {
        self.driver(driver).map(|d| d.device)
    }
    pub fn quota(&self, driver: DriverId) -> DriverQuota {
        self.driver(driver).map_or(DriverQuota::DENY, |d| d.quota)
    }
    pub fn occupancy(&self, driver: DriverId) -> DriverOccupancy {
        self.driver(driver)
            .map_or(DriverOccupancy::EMPTY, |d| d.occupancy)
    }
    pub fn epoch(&self, driver: DriverId) -> Option<DriverEpoch> {
        self.driver(driver).map(|d| d.epoch)
    }
    pub fn dma_mapping_count(&self) -> usize {
        self.dma.iter().flatten().count()
    }
    pub fn lease_count(&self) -> usize {
        self.leases.iter().flatten().count()
    }
    pub fn mmio_grant_bytes(&self, driver: DriverId, region: MmioRegionId) -> Option<u32> {
        self.regions
            .iter()
            .flatten()
            .find(|grant| grant.driver == driver && grant.id == region)
            .map(|grant| grant.bytes)
    }

    pub fn grant_mmio_region(
        &mut self,
        driver: DriverId,
        device: DeviceId,
        id: MmioRegionId,
        bytes: u32,
        access: MmioAccess,
        isolation: MmioIsolation,
    ) -> Result<(), ResourceError> {
        let d = self.driver(driver).ok_or(ResourceError::NoQuota)?;
        if d.device != device {
            return Err(ResourceError::WrongDevice);
        }
        if id.0 == 0 || bytes == 0 {
            return Err(ResourceError::BadRange);
        }
        if self
            .regions
            .iter()
            .flatten()
            .any(|r| r.id == id && r.driver != driver)
        {
            return Err(ResourceError::Duplicate);
        }
        if self
            .regions
            .iter()
            .flatten()
            .any(|r| r.id == id && r.driver == driver)
        {
            return Ok(());
        }
        let slot = self
            .regions
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        self.regions[slot] = Some(RegionGrant {
            driver,
            device,
            id,
            bytes,
            access,
            isolation,
        });
        Ok(())
    }

    pub fn grant_irq_source(
        &mut self,
        driver: DriverId,
        device: DeviceId,
        source: IrqSourceId,
    ) -> Result<(), ResourceError> {
        let d = self.driver(driver).ok_or(ResourceError::NoQuota)?;
        if d.device != device {
            return Err(ResourceError::WrongDevice);
        }
        if source.0 == 0 {
            return Err(ResourceError::BadIdentity);
        }
        if self
            .irq_grants
            .iter()
            .flatten()
            .any(|grant| grant.source == source && grant.driver != driver)
        {
            return Err(ResourceError::Duplicate);
        }
        if self
            .irq_grants
            .iter()
            .flatten()
            .any(|grant| grant.source == source && grant.driver == driver)
        {
            return Ok(());
        }
        let slot = self
            .irq_grants
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        self.irq_grants[slot] = Some(IrqGrant {
            driver,
            device,
            source,
        });
        Ok(())
    }

    /// Map one bounded subrange of a granted MMIO region into a driver.
    ///
    /// Every argument is load-bearing authority: the driver and device
    /// authenticate the caller, the epoch rejects a stale instance, and the
    /// region, offset, length, and access mode are the exact bound being
    /// enforced. Collapsing them into a struct would move the bound out of the
    /// signature without removing anything, which is why `shared_buffer.rs`'s
    /// `map`/`map_loan` carry the same allow.
    #[allow(clippy::too_many_arguments)]
    pub fn map_mmio<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        region: MmioRegionId,
        offset: u32,
        length: u32,
        access: MmioAccess,
    ) -> Result<MmioHandle, ResourceError> {
        let plan = self.prepare_map_mmio(driver, device, epoch, region, offset, length, access)?;
        let token = adapter.map_mmio(device, region, offset, length, access)?;
        self.commit_map_mmio(plan, token)
    }

    fn prepare_map_mmio(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        region: MmioRegionId,
        offset: u32,
        length: u32,
        access: MmioAccess,
    ) -> Result<MmioPlan, ResourceError> {
        let d = self.authorize(driver, device, epoch)?;
        let grant = self
            .regions
            .iter()
            .flatten()
            .find(|r| r.id == region)
            .copied()
            .ok_or(ResourceError::WrongRegion)?;
        if grant.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if grant.device != device {
            return Err(ResourceError::WrongDevice);
        }
        if grant.isolation != MmioIsolation::PageExclusive {
            return Err(ResourceError::BadRange);
        }
        if !grant.access.permits(access) {
            return Err(ResourceError::BadAccess);
        }
        let end = offset.checked_add(length).ok_or(ResourceError::BadRange)?;
        if length == 0 || end > grant.bytes {
            return Err(ResourceError::BadRange);
        }
        if self.mmio.iter().flatten().any(|m| {
            m.driver == driver && m.region == region && m.offset == offset && m.length == length
        }) {
            return Err(ResourceError::Duplicate);
        }
        if d.occupancy
            .mmio_mappings
            .checked_add(1)
            .is_none_or(|n| n > d.quota.mmio_mappings)
            || d.occupancy
                .mmio_bytes
                .checked_add(length)
                .is_none_or(|n| n > d.quota.mmio_bytes)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let slot = self
            .mmio
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        Ok(MmioPlan {
            slot,
            mapping: MmioMapping {
                id: MmioMappingId(self.next_mmio),
                driver,
                device,
                epoch,
                region,
                offset,
                length,
                access,
                token: 0,
            },
        })
    }

    pub fn read_mmio32<A: IoResourceAdapter>(
        &self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        region: MmioRegionId,
        offset: u32,
    ) -> Result<u32, ResourceError> {
        let grant = self.authorize_mmio_access(
            driver,
            device,
            epoch,
            region,
            offset,
            MmioAccess::ReadOnly,
        )?;
        adapter
            .read_mmio32(device, grant.id, offset)
            .map_err(Into::into)
    }
    pub fn write_mmio32<A: IoResourceAdapter>(
        &self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        region: MmioRegionId,
        offset: u32,
        value: u32,
    ) -> Result<(), ResourceError> {
        let grant = self.authorize_mmio_access(
            driver,
            device,
            epoch,
            region,
            offset,
            MmioAccess::ReadWrite,
        )?;
        adapter
            .write_mmio32(device, grant.id, offset, value)
            .map_err(Into::into)
    }
    fn authorize_mmio_access(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        region: MmioRegionId,
        offset: u32,
        access: MmioAccess,
    ) -> Result<RegionGrant, ResourceError> {
        self.authorize(driver, device, epoch)?;
        let grant = self
            .regions
            .iter()
            .flatten()
            .find(|r| r.id == region)
            .copied()
            .ok_or(ResourceError::WrongRegion)?;
        if grant.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if grant.device != device {
            return Err(ResourceError::WrongDevice);
        }
        if !grant.access.permits(access) {
            return Err(ResourceError::BadAccess);
        }
        if offset.checked_add(4).is_none_or(|end| end > grant.bytes) || !offset.is_multiple_of(4) {
            return Err(ResourceError::BadRange);
        }
        Ok(grant)
    }

    fn commit_map_mmio(
        &mut self,
        mut plan: MmioPlan,
        token: u64,
    ) -> Result<MmioHandle, ResourceError> {
        if token == 0 {
            return Err(ResourceError::Adapter(AdapterError::MapFailed));
        }
        let driver_slot =
            self.authorize_slot(plan.mapping.driver, plan.mapping.device, plan.mapping.epoch)?;
        if self.mmio[plan.slot].is_some() {
            return Err(ResourceError::Duplicate);
        }
        plan.mapping.token = token;
        self.mmio[plan.slot] = Some(plan.mapping);
        let o = &mut self.drivers[driver_slot].as_mut().unwrap().occupancy;
        o.mmio_bytes += plan.mapping.length;
        o.mmio_mappings += 1;
        self.next_mmio = self
            .next_mmio
            .checked_add(1)
            .ok_or(ResourceError::TableFull)?;
        Ok(MmioHandle {
            id: plan.mapping.id,
            driver: plan.mapping.driver,
            device: plan.mapping.device,
            region: plan.mapping.region,
            epoch: plan.mapping.epoch,
        })
    }

    pub fn declare_lease(
        &mut self,
        driver: DriverId,
        epoch: DriverEpoch,
        lease: LeaseId,
        pages: u32,
    ) -> Result<(), ResourceError> {
        let slot = self.authorize_driver_slot(driver, epoch)?;
        if lease.0 == 0 || pages == 0 {
            return Err(ResourceError::BadIdentity);
        }
        if let Some(existing) = self
            .leases
            .iter()
            .flatten()
            .find(|held| held.id == lease)
            .copied()
        {
            return if existing.driver == driver
                && existing.epoch == epoch
                && existing.pages == pages
            {
                Ok(())
            } else {
                Err(ResourceError::Duplicate)
            };
        }
        let d = self.drivers[slot].unwrap();
        if d.occupancy
            .buffer_loans
            .checked_add(1)
            .is_none_or(|n| n > d.quota.buffer_loans)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let lease_slot = self
            .leases
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        self.leases[lease_slot] = Some(Lease {
            driver,
            id: lease,
            epoch,
            pages,
            mappings: 0,
            requests: 0,
        });
        self.drivers[slot].as_mut().unwrap().occupancy.buffer_loans += 1;
        Ok(())
    }

    pub fn release_lease(
        &mut self,
        driver: DriverId,
        epoch: DriverEpoch,
        lease: LeaseId,
    ) -> Result<(), ResourceError> {
        self.authorize_driver_slot(driver, epoch)?;
        let slot = self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?;
        let held = self.leases[slot].unwrap();
        if held.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if held.epoch != epoch {
            return Err(ResourceError::StaleEpoch);
        }
        if held.mappings != 0 || held.requests != 0 {
            return Err(ResourceError::LeaseBusy);
        }
        self.leases[slot] = None;
        self.driver_mut(driver).unwrap().occupancy.buffer_loans -= 1;
        Ok(())
    }

    /// Settle a shared-buffer lease from the buffer authority plane. Every
    /// request and DMA mapping over it is revoked before the lease charge is
    /// returned; failed effects leave all logical state retryable.
    pub fn revoke_lease<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        lease: LeaseId,
    ) -> Result<ActionList, ResourceError> {
        let lease_slot = self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?;
        let held = self.leases[lease_slot].ok_or(ResourceError::LeaseNotLive)?;
        let driver_slot = self.authorize_driver_slot(held.driver, held.epoch)?;
        let mut actions = ActionList::new();
        for request in self.requests.iter().flatten().filter(|request| {
            self.dma_slot(request.mapping)
                .and_then(|slot| self.dma[slot])
                .is_some_and(|mapping| mapping.lease == Some(lease))
        }) {
            actions.push(AdapterAction::SettleRequest {
                request: request.id,
            })?;
        }
        for mapping in self
            .dma
            .iter()
            .flatten()
            .filter(|mapping| mapping.lease == Some(lease))
        {
            actions.push(AdapterAction::DestroyDma {
                token: mapping.token,
            })?;
        }
        for action in actions.iter() {
            adapter.perform(action)?;
        }
        let removed_ids = self.dma;
        self.requests
            .iter_mut()
            .filter(|request| {
                request.is_some_and(|request| {
                    removed_ids.iter().flatten().any(|mapping| {
                        mapping.id == request.mapping && mapping.lease == Some(lease)
                    })
                })
            })
            .for_each(|request| *request = None);
        let mappings = held.mappings;
        self.dma
            .iter_mut()
            .filter(|mapping| mapping.is_some_and(|mapping| mapping.lease == Some(lease)))
            .for_each(|mapping| *mapping = None);
        self.leases[lease_slot] = None;
        let occupancy = &mut self.drivers[driver_slot]
            .as_mut()
            .ok_or(ResourceError::NoQuota)?
            .occupancy;
        occupancy.dma_pages -= held.pages;
        occupancy.dma_mappings -= mappings;
        occupancy.outstanding_requests -= held.requests;
        occupancy.buffer_loans -= 1;
        Ok(actions)
    }

    pub fn create_dma_mapping<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        lease: LeaseId,
        direction: DmaDirection,
    ) -> Result<DmaHandle, ResourceError> {
        let plan = self.prepare_dma(driver, device, epoch, lease, direction)?;
        let (token, raw_iova) =
            adapter.create_dma_mapping(device, lease, plan.mapping.pages, direction)?;
        self.commit_dma(plan, token, raw_iova)
    }

    fn prepare_dma(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        lease: LeaseId,
        direction: DmaDirection,
    ) -> Result<DmaPlan, ResourceError> {
        let driver_slot = self.authorize_slot(driver, device, epoch)?;
        let lease_slot = self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?;
        let held = self.leases[lease_slot].unwrap();
        if held.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if held.epoch != epoch {
            return Err(ResourceError::StaleEpoch);
        }
        if self
            .dma
            .iter()
            .flatten()
            .any(|m| m.driver == driver && m.lease == Some(lease) && m.direction == Some(direction))
        {
            return Err(ResourceError::Duplicate);
        }
        let d = self.drivers[driver_slot].unwrap();
        let additional_pages = if held.mappings == 0 { held.pages } else { 0 };
        if d.occupancy
            .dma_pages
            .checked_add(additional_pages)
            .is_none_or(|n| n > d.quota.dma_pages)
            || d.occupancy
                .dma_mappings
                .checked_add(1)
                .is_none_or(|n| n > d.quota.dma_mappings)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let slot = self
            .dma
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        Ok(DmaPlan {
            slot,
            driver_slot,
            lease_slot,
            mapping: DmaMapping {
                id: DmaMappingId(self.next_dma),
                driver,
                device,
                epoch,
                lease: Some(lease),
                pages: held.pages,
                direction: Some(direction),
                token: 0,
                iova: Iova(0),
                requests: 0,
            },
        })
    }

    fn commit_dma(
        &mut self,
        mut plan: DmaPlan,
        token: u64,
        raw_iova: u64,
    ) -> Result<DmaHandle, ResourceError> {
        if token == 0 || raw_iova == 0 {
            return Err(ResourceError::Adapter(AdapterError::DmaFailed));
        }
        self.authorize_slot(plan.mapping.driver, plan.mapping.device, plan.mapping.epoch)?;
        if self.dma[plan.slot].is_some() {
            return Err(ResourceError::Duplicate);
        }
        plan.mapping.token = token;
        plan.mapping.iova = Iova(raw_iova);
        self.dma[plan.slot] = Some(plan.mapping);
        let lease = self.leases[plan.lease_slot]
            .as_mut()
            .ok_or(ResourceError::LeaseNotLive)?;
        lease.mappings += 1;
        let first_mapping = lease.mappings == 1;
        let o = &mut self.drivers[plan.driver_slot].as_mut().unwrap().occupancy;
        if first_mapping {
            o.dma_pages += plan.mapping.pages;
        }
        o.dma_mappings += 1;
        self.next_dma = self
            .next_dma
            .checked_add(1)
            .ok_or(ResourceError::TableFull)?;
        Ok(DmaHandle {
            id: plan.mapping.id,
            driver: plan.mapping.driver,
            epoch: plan.mapping.epoch,
            lease: plan.mapping.lease.ok_or(ResourceError::LeaseNotLive)?,
            direction: plan.mapping.direction.ok_or(ResourceError::BadAccess)?,
            iova: plan.mapping.iova,
        })
    }
    /// Allocate driver-owned bidirectional queue control memory. This has no
    /// `LeaseId` and cannot be reached through the payload-mapping API.
    pub fn map_device_queue<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        pages: u32,
    ) -> Result<QueueDmaHandle, ResourceError> {
        let driver_slot = self.authorize_slot(driver, device, epoch)?;
        if pages == 0 {
            return Err(ResourceError::BadRange);
        }
        let d = self.drivers[driver_slot].unwrap();
        if d.occupancy
            .dma_pages
            .checked_add(pages)
            .is_none_or(|n| n > d.quota.dma_pages)
            || d.occupancy
                .dma_mappings
                .checked_add(1)
                .is_none_or(|n| n > d.quota.dma_mappings)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let slot = self
            .dma
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        let id = DmaMappingId(self.next_dma);
        let (token, raw_iova) = adapter.create_device_queue(device, pages)?;
        if token == 0 || raw_iova == 0 {
            return Err(ResourceError::Adapter(AdapterError::DmaFailed));
        }
        self.authorize_slot(driver, device, epoch)?;
        if self.dma[slot].is_some() {
            return Err(ResourceError::Duplicate);
        }
        self.dma[slot] = Some(DmaMapping {
            id,
            driver,
            device,
            epoch,
            lease: None,
            pages,
            direction: None,
            token,
            iova: Iova(raw_iova),
            requests: 0,
        });
        let o = &mut self.drivers[driver_slot].as_mut().unwrap().occupancy;
        o.dma_pages += pages;
        o.dma_mappings += 1;
        self.next_dma = self
            .next_dma
            .checked_add(1)
            .ok_or(ResourceError::TableFull)?;
        Ok(QueueDmaHandle {
            id,
            driver,
            epoch,
            pages,
            iova: Iova(raw_iova),
        })
    }

    pub fn destroy_dma_mapping<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        handle: DmaHandle,
    ) -> Result<(), ResourceError> {
        let driver_slot = self.authorize_driver_slot(driver, handle.epoch)?;
        if handle.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        let slot = self.dma_slot(handle.id).ok_or(ResourceError::NotFound)?;
        let mapping = self.dma[slot].unwrap();
        if mapping.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if mapping.epoch != handle.epoch {
            return Err(ResourceError::StaleEpoch);
        }
        if mapping.requests != 0 {
            return Err(ResourceError::MappingBusy);
        }
        adapter.perform(AdapterAction::DestroyDma {
            token: mapping.token,
        })?;
        self.dma[slot] = None;
        let release_pages = if let Some(lease) = mapping.lease {
            let lease_slot = self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?;
            let held = self.leases[lease_slot]
                .as_mut()
                .ok_or(ResourceError::LeaseNotLive)?;
            held.mappings -= 1;
            held.mappings == 0
        } else {
            true
        };
        let o = &mut self.drivers[driver_slot].as_mut().unwrap().occupancy;
        if release_pages {
            o.dma_pages -= mapping.pages;
        }
        o.dma_mappings -= 1;
        Ok(())
    }

    pub fn destroy_dma_mapping_id<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        epoch: DriverEpoch,
        id: DmaMappingId,
    ) -> Result<(), ResourceError> {
        let driver_slot = self.authorize_driver_slot(driver, epoch)?;
        let slot = self.dma_slot(id).ok_or(ResourceError::NotFound)?;
        let mapping = self.dma[slot].ok_or(ResourceError::NotFound)?;
        if mapping.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if mapping.epoch != epoch {
            return Err(ResourceError::StaleEpoch);
        }
        if mapping.requests != 0 {
            return Err(ResourceError::MappingBusy);
        }
        adapter.perform(AdapterAction::DestroyDma {
            token: mapping.token,
        })?;
        self.dma[slot] = None;
        let release_pages = if let Some(lease) = mapping.lease
            && let Some(lease_slot) = self.lease_slot(lease)
        {
            let held = self.leases[lease_slot]
                .as_mut()
                .ok_or(ResourceError::LeaseNotLive)?;
            held.mappings -= 1;
            held.mappings == 0
        } else {
            true
        };
        let occupancy = &mut self.drivers[driver_slot]
            .as_mut()
            .ok_or(ResourceError::NoQuota)?
            .occupancy;
        if release_pages {
            occupancy.dma_pages -= mapping.pages;
        }
        occupancy.dma_mappings -= 1;
        Ok(())
    }

    pub fn settle_request_id(
        &mut self,
        driver: DriverId,
        epoch: DriverEpoch,
        mapping: DmaMappingId,
        id: RequestId,
    ) -> Result<(), ResourceError> {
        self.settle_request(
            driver,
            RequestHandle {
                driver,
                id,
                epoch,
                mapping,
            },
        )
    }

    pub fn begin_request(
        &mut self,
        driver: DriverId,
        epoch: DriverEpoch,
        id: RequestId,
        mapping_id: DmaMappingId,
    ) -> Result<RequestHandle, ResourceError> {
        let driver_slot = self.authorize_driver_slot(driver, epoch)?;
        if id.0 == 0 {
            return Err(ResourceError::BadIdentity);
        }
        if self
            .requests
            .iter()
            .flatten()
            .any(|r| r.driver == driver && r.id == id)
        {
            return Err(ResourceError::Duplicate);
        }
        let dma_slot = self.dma_slot(mapping_id).ok_or(ResourceError::NotFound)?;
        let mapping = self.dma[dma_slot].unwrap();
        if mapping.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if mapping.epoch != epoch {
            return Err(ResourceError::StaleEpoch);
        }
        let d = self.drivers[driver_slot].unwrap();
        if d.occupancy
            .outstanding_requests
            .checked_add(1)
            .is_none_or(|n| n > d.quota.outstanding_requests)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let slot = self
            .requests
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        let lease = mapping.lease.ok_or(ResourceError::LeaseNotLive)?;
        let lease_slot = self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?;
        self.requests[slot] = Some(Request {
            driver,
            id,
            epoch,
            mapping: mapping_id,
        });
        self.dma[dma_slot].as_mut().unwrap().requests += 1;
        self.leases[lease_slot].as_mut().unwrap().requests += 1;
        self.drivers[driver_slot]
            .as_mut()
            .unwrap()
            .occupancy
            .outstanding_requests += 1;
        Ok(RequestHandle {
            driver,
            id,
            epoch,
            mapping: mapping_id,
        })
    }

    pub fn settle_request(
        &mut self,
        driver: DriverId,
        handle: RequestHandle,
    ) -> Result<(), ResourceError> {
        let driver_slot = self.authorize_driver_slot(driver, handle.epoch)?;
        if handle.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        let slot = self
            .requests
            .iter()
            .position(|r| r.is_some_and(|r| r.driver == driver && r.id == handle.id))
            .ok_or(ResourceError::RequestNotLive)?;
        let request = self.requests[slot].unwrap();
        if request.epoch != handle.epoch || request.mapping != handle.mapping {
            return Err(ResourceError::StaleEpoch);
        }
        let dma_slot = self
            .dma_slot(request.mapping)
            .ok_or(ResourceError::NotFound)?;
        let lease = self.dma[dma_slot]
            .unwrap()
            .lease
            .ok_or(ResourceError::LeaseNotLive)?;
        self.requests[slot] = None;
        self.dma[dma_slot].as_mut().unwrap().requests -= 1;
        self.leases[self.lease_slot(lease).ok_or(ResourceError::LeaseNotLive)?]
            .as_mut()
            .unwrap()
            .requests -= 1;
        self.drivers[driver_slot]
            .as_mut()
            .unwrap()
            .occupancy
            .outstanding_requests -= 1;
        Ok(())
    }

    pub fn bind_irq<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        source: IrqSourceId,
    ) -> Result<(), ResourceError> {
        let plan = self.prepare_irq(driver, device, epoch, source)?;
        adapter.bind_irq(device, source)?;
        self.irqs[plan.slot] = Some(plan.binding);
        self.drivers[plan.driver_slot]
            .as_mut()
            .unwrap()
            .occupancy
            .irq_sources += 1;
        Ok(())
    }

    fn prepare_irq(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
        source: IrqSourceId,
    ) -> Result<IrqPlan, ResourceError> {
        let driver_slot = self.authorize_slot(driver, device, epoch)?;
        if source.0 == 0 {
            return Err(ResourceError::BadIdentity);
        }
        let grant = self
            .irq_grants
            .iter()
            .flatten()
            .find(|grant| grant.source == source)
            .copied()
            .ok_or(ResourceError::WrongSource)?;
        if grant.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        if grant.device != device {
            return Err(ResourceError::WrongDevice);
        }
        if self.irqs.iter().flatten().any(|irq| irq.source == source) {
            return Err(ResourceError::Duplicate);
        }
        let d = self.drivers[driver_slot].unwrap();
        if d.occupancy
            .irq_sources
            .checked_add(1)
            .is_none_or(|n| n > d.quota.irq_sources)
        {
            return Err(ResourceError::QuotaExceeded);
        }
        let slot = self
            .irqs
            .iter()
            .position(Option::is_none)
            .ok_or(ResourceError::TableFull)?;
        Ok(IrqPlan {
            slot,
            driver_slot,
            binding: IrqBinding {
                driver,
                device,
                source,
                epoch,
                next_sequence: 1,
                pending: None,
                last_acked: 0,
            },
        })
    }

    /// Called only by the root's authenticated IRQ dispatch path.
    pub fn interrupt_arrived(&mut self, source: IrqSourceId) -> Result<IrqHandle, ResourceError> {
        let slot = self.irq_slot(source).ok_or(ResourceError::WrongSource)?;
        let irq = self.irqs[slot].as_mut().unwrap();
        if irq.pending.is_some() {
            return Err(ResourceError::Duplicate);
        }
        let sequence = irq.next_sequence;
        irq.next_sequence = irq
            .next_sequence
            .checked_add(1)
            .ok_or(ResourceError::TableFull)?;
        irq.pending = Some(sequence);
        Ok(IrqHandle {
            driver: irq.driver,
            source,
            epoch: irq.epoch,
            sequence,
        })
    }

    pub fn ack_irq<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
        handle: IrqHandle,
    ) -> Result<(), ResourceError> {
        self.authorize_driver_slot(driver, handle.epoch)?;
        if handle.driver != driver {
            return Err(ResourceError::WrongDriver);
        }
        let slot = self
            .irq_slot(handle.source)
            .ok_or(ResourceError::WrongSource)?;
        let irq = self.irqs[slot].as_mut().unwrap();
        if irq.driver != driver {
            return Err(ResourceError::WrongSource);
        }
        if irq.epoch != handle.epoch {
            return Err(ResourceError::StaleEpoch);
        }
        if irq.pending != Some(handle.sequence) {
            return if irq.last_acked == handle.sequence {
                Err(ResourceError::DuplicateAck)
            } else {
                Err(ResourceError::NoInterrupt)
            };
        }
        adapter.ack_irq(handle.source)?;
        irq.pending = None;
        irq.last_acked = handle.sequence;
        Ok(())
    }

    /// Revoke every external effect, settle requests, return every charge, and
    /// issue the same driver a fresh epoch. No logical state changes if an
    /// adapter action fails, so the deterministic action list is retryable.
    pub fn reclaim_driver<A: IoResourceAdapter>(
        &mut self,
        adapter: &mut A,
        driver: DriverId,
    ) -> Result<(ActionList, DriverEpoch), ResourceError> {
        let driver_slot = self.driver_slot(driver).ok_or(ResourceError::NoQuota)?;
        let mut actions = ActionList::new();
        for request in self
            .requests
            .iter()
            .flatten()
            .filter(|r| r.driver == driver)
        {
            actions.push(AdapterAction::SettleRequest {
                request: request.id,
            })?;
        }
        for mapping in self.dma.iter().flatten().filter(|m| m.driver == driver) {
            actions.push(AdapterAction::DestroyDma {
                token: mapping.token,
            })?;
        }
        for irq in self.irqs.iter().flatten().filter(|i| i.driver == driver) {
            actions.push(AdapterAction::UnbindIrq { source: irq.source })?;
        }
        for mapping in self.mmio.iter().flatten().filter(|m| m.driver == driver) {
            actions.push(AdapterAction::UnmapMmio {
                token: mapping.token,
                device: mapping.device,
                length: mapping.length,
            })?;
        }
        for action in actions.iter() {
            adapter.perform(action)?;
        }
        self.requests
            .iter_mut()
            .filter(|r| r.is_some_and(|r| r.driver == driver))
            .for_each(|r| *r = None);
        self.dma
            .iter_mut()
            .filter(|m| m.is_some_and(|m| m.driver == driver))
            .for_each(|m| *m = None);
        self.irqs
            .iter_mut()
            .filter(|i| i.is_some_and(|i| i.driver == driver))
            .for_each(|i| *i = None);
        self.mmio
            .iter_mut()
            .filter(|m| m.is_some_and(|m| m.driver == driver))
            .for_each(|m| *m = None);
        self.leases
            .iter_mut()
            .filter(|l| l.is_some_and(|l| l.driver == driver))
            .for_each(|l| *l = None);
        self.regions
            .iter_mut()
            .filter(|grant| grant.is_some_and(|grant| grant.driver == driver))
            .for_each(|grant| *grant = None);
        self.irq_grants
            .iter_mut()
            .filter(|grant| grant.is_some_and(|grant| grant.driver == driver))
            .for_each(|grant| *grant = None);
        let entry = self.drivers[driver_slot].as_mut().unwrap();
        entry.occupancy = DriverOccupancy::EMPTY;
        entry.epoch = DriverEpoch(
            entry
                .epoch
                .0
                .checked_add(1)
                .ok_or(ResourceError::TableFull)?,
        );
        Ok((actions, entry.epoch))
    }

    fn driver_slot(&self, id: DriverId) -> Option<usize> {
        self.drivers
            .iter()
            .position(|d| d.is_some_and(|d| d.id == id))
    }
    fn driver(&self, id: DriverId) -> Option<Driver> {
        self.driver_slot(id).and_then(|s| self.drivers[s])
    }
    fn driver_mut(&mut self, id: DriverId) -> Option<&mut Driver> {
        let s = self.driver_slot(id)?;
        self.drivers[s].as_mut()
    }
    fn authorize_driver_slot(
        &self,
        driver: DriverId,
        epoch: DriverEpoch,
    ) -> Result<usize, ResourceError> {
        let slot = self.driver_slot(driver).ok_or(ResourceError::NoQuota)?;
        if self.drivers[slot].unwrap().epoch != epoch {
            return Err(ResourceError::StaleEpoch);
        }
        Ok(slot)
    }
    fn authorize_slot(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
    ) -> Result<usize, ResourceError> {
        let slot = self.authorize_driver_slot(driver, epoch)?;
        if self.drivers[slot].unwrap().device != device {
            return Err(ResourceError::WrongDevice);
        }
        Ok(slot)
    }
    fn authorize(
        &self,
        driver: DriverId,
        device: DeviceId,
        epoch: DriverEpoch,
    ) -> Result<Driver, ResourceError> {
        Ok(self.drivers[self.authorize_slot(driver, device, epoch)?].unwrap())
    }
    fn lease_slot(&self, id: LeaseId) -> Option<usize> {
        self.leases
            .iter()
            .position(|l| l.is_some_and(|l| l.id == id))
    }
    fn dma_slot(&self, id: DmaMappingId) -> Option<usize> {
        self.dma.iter().position(|m| m.is_some_and(|m| m.id == id))
    }
    fn irq_slot(&self, id: IrqSourceId) -> Option<usize> {
        self.irqs
            .iter()
            .position(|i| i.is_some_and(|i| i.source == id))
    }
}

impl Default for ResourceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DRIVER: DriverId = DriverId(1);
    const OTHER: DriverId = DriverId(2);
    const DEVICE: DeviceId = DeviceId(10);
    const OTHER_DEVICE: DeviceId = DeviceId(11);
    const REGION: MmioRegionId = MmioRegionId(20);
    const IRQ: IrqSourceId = IrqSourceId(30);
    const LEASE: LeaseId = LeaseId(40);
    const QUOTA: DriverQuota = DriverQuota {
        mmio_bytes: 0x1000,
        mmio_mappings: 2,
        dma_pages: 4,
        dma_mappings: 2,
        irq_sources: 1,
        outstanding_requests: 2,
        buffer_loans: 2,
    };

    struct RecordingAdapter {
        calls: usize,
        fail_at: Option<usize>,
        actions: [Option<AdapterAction>; MAX_ACTIONS],
    }
    impl RecordingAdapter {
        const fn new() -> Self {
            Self {
                calls: 0,
                fail_at: None,
                actions: [None; MAX_ACTIONS],
            }
        }
        fn failing_at(call: usize) -> Self {
            Self {
                fail_at: Some(call),
                ..Self::new()
            }
        }
        fn call(&mut self, action: Option<AdapterAction>) -> Result<(), AdapterError> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at == Some(call) {
                return Err(AdapterError::TeardownFailed);
            }
            if let Some(action) = action {
                self.actions[call] = Some(action);
            }
            Ok(())
        }
    }
    impl IoResourceAdapter for RecordingAdapter {
        fn map_mmio(
            &mut self,
            _: DeviceId,
            _: MmioRegionId,
            _: u32,
            _: u32,
            _: MmioAccess,
        ) -> Result<u64, AdapterError> {
            self.call(None)?;
            Ok(100 + self.calls as u64)
        }
        fn read_mmio32(
            &mut self,
            _: DeviceId,
            _: MmioRegionId,
            _: u32,
        ) -> Result<u32, AdapterError> {
            self.call(None)?;
            Ok(0x7472_6976)
        }
        fn write_mmio32(
            &mut self,
            _: DeviceId,
            _: MmioRegionId,
            _: u32,
            _: u32,
        ) -> Result<(), AdapterError> {
            self.call(None)
        }
        fn bind_irq(&mut self, _: DeviceId, _: IrqSourceId) -> Result<(), AdapterError> {
            self.call(None)
        }
        fn ack_irq(&mut self, _: IrqSourceId) -> Result<(), AdapterError> {
            self.call(None)
        }
        fn create_dma_mapping(
            &mut self,
            _: DeviceId,
            _: LeaseId,
            _: u32,
            _: DmaDirection,
        ) -> Result<(u64, u64), AdapterError> {
            self.call(None)?;
            Ok((
                200 + self.calls as u64,
                0x1000_0000 + self.calls as u64 * PAGE_SIZE as u64,
            ))
        }
        fn create_device_queue(&mut self, _: DeviceId, _: u32) -> Result<(u64, u64), AdapterError> {
            self.call(None)?;
            Ok((
                300 + self.calls as u64,
                0x2000_0000 + self.calls as u64 * PAGE_SIZE as u64,
            ))
        }
        fn perform(&mut self, action: AdapterAction) -> Result<(), AdapterError> {
            self.call(Some(action))
        }
    }

    fn table() -> (ResourceTable, DriverEpoch) {
        let mut table = ResourceTable::new();
        let epoch = table.declare_quota(DRIVER, DEVICE, QUOTA).unwrap();
        table.declare_quota(OTHER, OTHER_DEVICE, QUOTA).unwrap();
        table
            .grant_mmio_region(
                DRIVER,
                DEVICE,
                REGION,
                0x1000,
                MmioAccess::ReadWrite,
                MmioIsolation::PageExclusive,
            )
            .unwrap();
        table.grant_irq_source(DRIVER, DEVICE, IRQ).unwrap();
        (table, epoch)
    }

    /// B84: two driver instances of one executable, one device each.
    ///
    /// This is the shape `sel4-recovery` and `sel4-transfer` boot. Every
    /// per-device identity must be derived from the declared ordinal rather
    /// than fixed, because two instances asking for region 1 and source 1 —
    /// which is what the old constants produced — collide on the uniqueness
    /// checks below and the second install fails outright.
    #[test]
    fn two_drivers_each_hold_their_own_device() {
        let mut table = ResourceTable::new();
        table.declare_quota(DRIVER, DEVICE, QUOTA).unwrap();
        table.declare_quota(OTHER, OTHER_DEVICE, QUOTA).unwrap();
        assert_eq!(table.device(DRIVER), Some(DEVICE));
        assert_eq!(table.device(OTHER), Some(OTHER_DEVICE));

        // Distinct per-device identities install cleanly.
        for (driver, device, region, irq) in [
            (
                DRIVER,
                DEVICE,
                MmioRegionId(DEVICE.0),
                IrqSourceId(DEVICE.0),
            ),
            (
                OTHER,
                OTHER_DEVICE,
                MmioRegionId(OTHER_DEVICE.0),
                IrqSourceId(OTHER_DEVICE.0),
            ),
        ] {
            table
                .grant_mmio_region(
                    driver,
                    device,
                    region,
                    0x1000,
                    MmioAccess::ReadWrite,
                    MmioIsolation::PageExclusive,
                )
                .unwrap();
            table.grant_irq_source(driver, device, irq).unwrap();
        }

        // A shared resource identity across two drivers is refused, so the
        // pre-B84 arrangement cannot silently come back.
        assert_eq!(
            table.grant_irq_source(OTHER, OTHER_DEVICE, IrqSourceId(DEVICE.0)),
            Err(ResourceError::Duplicate)
        );
        assert_eq!(
            table.grant_mmio_region(
                OTHER,
                OTHER_DEVICE,
                MmioRegionId(DEVICE.0),
                0x1000,
                MmioAccess::ReadWrite,
                MmioIsolation::PageExclusive,
            ),
            Err(ResourceError::Duplicate)
        );

        // And neither driver can reach the other's device even holding its own
        // valid epoch: the device is checked against the installed record.
        assert_eq!(
            table.grant_irq_source(DRIVER, OTHER_DEVICE, IrqSourceId(99)),
            Err(ResourceError::WrongDevice)
        );
    }

    #[test]
    fn mmio_refusals_precede_adapter_calls() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        for result in [
            table.map_mmio(
                &mut adapter,
                DRIVER,
                OTHER_DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly,
            ),
            table.map_mmio(
                &mut adapter,
                OTHER,
                OTHER_DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly,
            ),
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0xfff,
                2,
                MmioAccess::ReadOnly,
            ),
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                0,
                MmioAccess::ReadOnly,
            ),
        ] {
            assert!(result.is_err());
        }
        assert_eq!(adapter.calls, 0);
        let handle = table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly,
            )
            .unwrap();
        assert_eq!(handle.region, REGION);
        assert_eq!(adapter.calls, 1);
        assert_eq!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly
            ),
            Err(ResourceError::Duplicate)
        );
        assert_eq!(adapter.calls, 1);
    }

    #[test]
    fn readonly_region_refuses_write_before_effect() {
        let mut table = ResourceTable::new();
        let epoch = table.declare_quota(DRIVER, DEVICE, QUOTA).unwrap();
        table
            .grant_mmio_region(
                DRIVER,
                DEVICE,
                REGION,
                32,
                MmioAccess::ReadOnly,
                MmioIsolation::PageExclusive,
            )
            .unwrap();
        let mut adapter = RecordingAdapter::new();
        assert_eq!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadWrite
            ),
            Err(ResourceError::BadAccess)
        );
        assert_eq!(adapter.calls, 0);
    }

    #[test]
    fn shared_granule_refuses_direct_map_but_mediates_exact_range() {
        let mut table = ResourceTable::new();
        let epoch = table.declare_quota(DRIVER, DEVICE, QUOTA).unwrap();
        table
            .grant_mmio_region(
                DRIVER,
                DEVICE,
                REGION,
                0x200,
                MmioAccess::ReadWrite,
                MmioIsolation::SharedGranule,
            )
            .unwrap();
        let mut adapter = RecordingAdapter::new();
        assert_eq!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                0x200,
                MmioAccess::ReadWrite
            ),
            Err(ResourceError::BadRange)
        );
        assert_eq!(adapter.calls, 0);
        assert_eq!(
            table.read_mmio32(&mut adapter, DRIVER, DEVICE, epoch, REGION, 0),
            Ok(0x7472_6976)
        );
        assert_eq!(
            table.read_mmio32(&mut adapter, DRIVER, DEVICE, epoch, REGION, 0x200),
            Err(ResourceError::BadRange)
        );
        assert_eq!(
            table.read_mmio32(
                &mut adapter,
                DRIVER,
                DEVICE,
                DriverEpoch(epoch.0 + 1),
                REGION,
                0
            ),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(adapter.calls, 1);
    }

    #[test]
    fn dma_is_per_live_lease_direction_scoped_and_account_bounded() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        assert_eq!(
            table.create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead
            ),
            Err(ResourceError::LeaseNotLive)
        );
        assert_eq!(adapter.calls, 0);
        table.declare_lease(DRIVER, epoch, LEASE, 3).unwrap();
        let read = table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead,
            )
            .unwrap();
        assert_ne!(read.iova().value(), 0);
        assert_eq!(
            table.create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead
            ),
            Err(ResourceError::Duplicate)
        );
        let write = table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceWrite,
            )
            .unwrap();
        assert_ne!(write.iova().value(), 0);
        assert_eq!(adapter.calls, 2);
        assert_eq!(table.occupancy(DRIVER).dma_pages, 3);
        assert_eq!(table.occupancy(DRIVER).dma_mappings, 2);
    }
    #[test]
    fn queue_dma_is_driver_owned_charged_and_reclaimed() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        let queue = table
            .map_device_queue(&mut adapter, DRIVER, DEVICE, epoch, 2)
            .unwrap();
        assert_ne!(queue.iova().value(), 0);
        assert_eq!(table.occupancy(DRIVER).dma_pages, 2);
        assert_eq!(
            table.create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead
            ),
            Err(ResourceError::LeaseNotLive)
        );
        assert_eq!(
            table.map_device_queue(&mut adapter, DRIVER, DEVICE, DriverEpoch(epoch.0 + 1), 1),
            Err(ResourceError::StaleEpoch)
        );
        let (actions, fresh) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
        assert_ne!(fresh, epoch);
    }

    #[test]
    fn request_keeps_dma_and_lease_charged_until_settled() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table.declare_lease(DRIVER, epoch, LEASE, 2).unwrap();
        let dma = table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceWrite,
            )
            .unwrap();
        let request = table
            .begin_request(DRIVER, epoch, RequestId(1), dma.id)
            .unwrap();
        assert_eq!(
            table.destroy_dma_mapping(&mut adapter, DRIVER, dma),
            Err(ResourceError::MappingBusy)
        );
        assert_eq!(
            table.release_lease(DRIVER, epoch, LEASE),
            Err(ResourceError::LeaseBusy)
        );
        table.settle_request(DRIVER, request).unwrap();
        table
            .destroy_dma_mapping(&mut adapter, DRIVER, dma)
            .unwrap();
        table.release_lease(DRIVER, epoch, LEASE).unwrap();
        assert_eq!(table.occupancy(DRIVER).dma_pages, 0);
        assert_eq!(table.occupancy(DRIVER).buffer_loans, 0);
    }

    #[test]
    fn interrupt_source_spoof_duplicate_and_stale_ack_fail_closed() {
        let (mut table, epoch) = table();
        assert_eq!(table.epoch(OTHER), Some(DriverEpoch(1)));
        let mut adapter = RecordingAdapter::new();
        assert_eq!(
            table.bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IrqSourceId(999)),
            Err(ResourceError::WrongSource)
        );
        assert_eq!(adapter.calls, 0);
        table
            .bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ)
            .unwrap();
        let handle = table.interrupt_arrived(IRQ).unwrap();
        let mut spoofed = handle;
        spoofed.source = IrqSourceId(999);
        assert_eq!(
            table.ack_irq(&mut adapter, DRIVER, spoofed),
            Err(ResourceError::WrongSource)
        );
        assert_eq!(
            table.ack_irq(&mut adapter, OTHER, handle),
            Err(ResourceError::WrongDriver)
        );
        table.ack_irq(&mut adapter, DRIVER, handle).unwrap();
        assert_eq!(
            table.ack_irq(&mut adapter, DRIVER, handle),
            Err(ResourceError::DuplicateAck)
        );
        let fresh = table.interrupt_arrived(IRQ).unwrap();
        let mut stale = fresh;
        stale.epoch = DriverEpoch(epoch.0 - 1);
        assert_eq!(
            table.ack_irq(&mut adapter, DRIVER, stale),
            Err(ResourceError::StaleEpoch)
        );
    }

    #[test]
    fn stale_handles_from_prior_epoch_fail_before_effect() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table.declare_lease(DRIVER, epoch, LEASE, 1).unwrap();
        let dma = table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead,
            )
            .unwrap();
        table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        let calls = adapter.calls;
        assert_eq!(
            table.destroy_dma_mapping(&mut adapter, DRIVER, dma),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly
            ),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(adapter.calls, calls);
    }

    #[test]
    fn queue_and_payload_reclaim_return_every_dma_charge() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table.declare_lease(DRIVER, epoch, LEASE, 2).unwrap();
        table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead,
            )
            .unwrap();
        table
            .map_device_queue(&mut adapter, DRIVER, DEVICE, epoch, 2)
            .unwrap();
        assert_eq!(table.occupancy(DRIVER).dma_pages, 4);
        assert_eq!(table.dma_mapping_count(), 2);
        let (_, fresh) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(fresh, DriverEpoch(epoch.0 + 1));
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
        assert_eq!(table.dma_mapping_count(), 0);
        assert_eq!(table.lease_count(), 0);
    }

    #[test]
    fn lease_settlement_revokes_payload_dma_and_is_retryable() {
        let (mut table, epoch) = table();
        let mut setup = RecordingAdapter::new();
        table.declare_lease(DRIVER, epoch, LEASE, 2).unwrap();
        table
            .create_dma_mapping(
                &mut setup,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceWrite,
            )
            .unwrap();
        let mut failing = RecordingAdapter::failing_at(0);
        assert!(matches!(
            table.revoke_lease(&mut failing, LEASE),
            Err(ResourceError::Adapter(_))
        ));
        assert_eq!(table.dma_mapping_count(), 1);
        assert_eq!(table.occupancy(DRIVER).dma_pages, 2);
        let mut retry = RecordingAdapter::new();
        let actions = table.revoke_lease(&mut retry, LEASE).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(table.dma_mapping_count(), 0);
        assert_eq!(table.lease_count(), 0);
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    #[test]
    fn driver_death_first_leaves_lease_settlement_closed() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table.declare_lease(DRIVER, epoch, LEASE, 1).unwrap();
        table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead,
            )
            .unwrap();
        table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(
            table.revoke_lease(&mut adapter, LEASE),
            Err(ResourceError::LeaseNotLive)
        );
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    #[test]
    fn failed_mmio_map_leaves_device_usable() {
        let (mut table, epoch) = table();
        let mut failed = RecordingAdapter::failing_at(0);
        assert!(matches!(
            table.map_mmio(
                &mut failed,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                PAGE_SIZE,
                MmioAccess::ReadWrite,
            ),
            Err(ResourceError::Adapter(_))
        ));
        let mut retry = RecordingAdapter::new();
        table
            .map_mmio(
                &mut retry,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                PAGE_SIZE,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        assert_eq!(
            table.read_mmio32(&mut retry, DRIVER, DEVICE, epoch, REGION, 0),
            Ok(0x7472_6976)
        );
    }
    #[test]
    fn mediated_mmio_refuses_in_granule_offset_outside_grant() {
        assert_eq!(mediated_mmio_offset(0x200, 0xe00, 0x200), None);
        assert_eq!(mediated_mmio_offset(0x200, 0xe00, 0x1fc), Some(0xffc));
    }

    #[test]
    fn failed_queue_request_begin_leaves_mapping_destroyable() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        let queue = table
            .map_device_queue(&mut adapter, DRIVER, DEVICE, epoch, 1)
            .unwrap();
        assert_eq!(
            table.begin_request(DRIVER, epoch, RequestId(1), queue.id),
            Err(ResourceError::LeaseNotLive)
        );
        table
            .destroy_dma_mapping_id(&mut adapter, DRIVER, epoch, queue.id)
            .unwrap();
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    #[test]
    fn adapter_failure_on_queue_commits_no_accounting() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::failing_at(0);
        assert!(matches!(
            table.map_device_queue(&mut adapter, DRIVER, DEVICE, epoch, 1),
            Err(ResourceError::Adapter(_))
        ));
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
        assert_eq!(table.dma_mapping_count(), 0);
    }

    #[test]
    fn adapter_failure_never_commits_accounting() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::failing_at(0);
        assert!(matches!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                4,
                MmioAccess::ReadOnly
            ),
            Err(ResourceError::Adapter(_))
        ));
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    #[test]
    fn crash_restart_returns_every_charge_and_issues_fresh_epoch() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        table
            .bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ)
            .unwrap();
        table.declare_lease(DRIVER, epoch, LEASE, 2).unwrap();
        let dma = table
            .create_dma_mapping(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                LEASE,
                DmaDirection::DeviceRead,
            )
            .unwrap();
        table
            .begin_request(DRIVER, epoch, RequestId(9), dma.id)
            .unwrap();
        let before = adapter.calls;
        let (actions, fresh) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(actions.len(), 4);
        assert_eq!(adapter.calls, before + 4);
        assert_eq!(fresh, DriverEpoch(epoch.0 + 1));
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    #[test]
    fn failed_reclaim_is_retryable_without_returning_charges() {
        let (mut table, epoch) = table();
        let mut setup = RecordingAdapter::new();
        table
            .map_mmio(
                &mut setup,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadOnly,
            )
            .unwrap();
        let mut failing = RecordingAdapter::failing_at(0);
        assert!(matches!(
            table.reclaim_driver(&mut failing, DRIVER),
            Err(ResourceError::Adapter(_))
        ));
        assert_eq!(table.occupancy(DRIVER).mmio_mappings, 1);
        let mut retry = RecordingAdapter::new();
        assert!(table.reclaim_driver(&mut retry, DRIVER).is_ok());
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    /// Teardown must name every live external effect: a device frame left
    /// mapped in a dead task's VSpace, or an IRQ still bound to its
    /// notification, hands live hardware authority to the replacement.
    #[test]
    fn reclaim_emits_unmap_and_unbind_for_every_live_effect() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        table
            .bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ)
            .unwrap();
        let (actions, _) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(actions.len(), 2);
        assert!(
            actions.iter().any(
                |action| matches!(action, AdapterAction::UnbindIrq { source } if source == IRQ)
            )
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, AdapterAction::UnmapMmio { .. }))
        );
        // Unmaps follow unbinds: an interrupt cannot arrive at a torn-down frame.
        assert!(matches!(
            actions.get(0),
            Some(AdapterAction::UnbindIrq { .. })
        ));
        assert!(matches!(
            actions.get(1),
            Some(AdapterAction::UnmapMmio { .. })
        ));
    }

    #[test]
    fn repeated_reclamation_is_idempotent() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        table
            .bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ)
            .unwrap();
        let (first, fresh) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(first.len(), 2);
        let calls = adapter.calls;
        let (second, again) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert!(second.is_empty());
        assert_eq!(adapter.calls, calls);
        assert_eq!(again, DriverEpoch(fresh.0 + 1));
        assert_eq!(table.occupancy(DRIVER), DriverOccupancy::EMPTY);
    }

    /// A replacement instance rebinds under the epoch reclamation issued, and
    /// every predecessor-epoch operation fails closed against it.
    #[test]
    fn predecessor_epoch_fails_closed_under_fresh_epoch() {
        let (mut table, epoch) = table();
        let mut adapter = RecordingAdapter::new();
        table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        table
            .bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ)
            .unwrap();
        let (_, fresh) = table.reclaim_driver(&mut adapter, DRIVER).unwrap();
        assert_eq!(
            table.declare_quota_at_epoch(DRIVER, DEVICE, QUOTA, fresh),
            Ok(fresh)
        );
        table
            .grant_mmio_region(
                DRIVER,
                DEVICE,
                REGION,
                0x1000,
                MmioAccess::ReadWrite,
                MmioIsolation::PageExclusive,
            )
            .unwrap();
        table.grant_irq_source(DRIVER, DEVICE, IRQ).unwrap();
        assert_eq!(table.epoch(DRIVER), Some(fresh));
        assert_eq!(
            table.map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                epoch,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite
            ),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(
            table.read_mmio32(&mut adapter, DRIVER, DEVICE, epoch, REGION, 0),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(
            table.bind_irq(&mut adapter, DRIVER, DEVICE, epoch, IRQ),
            Err(ResourceError::StaleEpoch)
        );
        assert_eq!(
            table.declare_lease(DRIVER, epoch, LEASE, 1),
            Err(ResourceError::StaleEpoch)
        );
        // The fresh identity still works, so the refusal is epoch-scoped rather
        // than a dead driver row.
        table
            .map_mmio(
                &mut adapter,
                DRIVER,
                DEVICE,
                fresh,
                REGION,
                0,
                64,
                MmioAccess::ReadWrite,
            )
            .unwrap();
        assert_eq!(table.occupancy(DRIVER).mmio_mappings, 1);
    }
}
