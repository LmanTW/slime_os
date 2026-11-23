//! Deterministic BootInfo CSlot and untyped allocation for `slime-root`.
//!
//! Global objects (devices and shared buffers included) remain monotonic. Child
//! tasks are different: each is built below a derived untyped whose capability
//! is the task's lifetime anchor. Revoking that anchor removes every task object
//! and every alias derived from one of them. The anchor is then deleted and its
//! dedicated parent untyped can retype the same physical region for a later
//! task. Root CSlots are managed by a bounded bitmap and are returned only after
//! the corresponding capability is known to be gone.

pub mod elastic;
mod funding;
#[cfg(test)]
mod funding_tests;
mod global_backing;
pub mod guarantee_vault;
mod infrastructure;
mod leaf_spans;
#[cfg(test)]
pub(crate) use leaf_spans::host::{bits as host_leaf_spans, release as host_release_leaf_spans};
pub(crate) use leaf_spans::{LeafSpanBits, MAX_WINDOW_SPANS};
mod extent_buddy;
mod mapping_tables;
mod preserved;
mod qualification;
mod record_tables;
mod segmented;
mod shared_backing;
mod slots;
#[cfg(test)]
mod slots_tests;
use slots::{SlotPlan, SlotPool};

#[cfg(slime_b38_force_unwind)]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(slime_private_fail_large_map)]
use core::sync::atomic::{AtomicBool as PrivateMapAtomicBool, Ordering as PrivateMapOrdering};
#[cfg(slime_private_fail_second_allocation)]
use core::sync::atomic::{
    AtomicBool as PrivateAllocationAtomicBool, Ordering as PrivateAllocationOrdering,
};

#[cfg(slime_b38_force_unwind)]
static FORCE_UNWIND_ONCE: AtomicBool = AtomicBool::new(true);

#[cfg(slime_b38_force_unwind)]
pub(crate) fn take_forced_unwind() -> bool {
    FORCE_UNWIND_ONCE.swap(false, Ordering::Relaxed)
}

#[cfg(slime_private_fail_second_allocation)]
static FORCE_PRIVATE_SECOND_ALLOCATION_FAILURE: PrivateAllocationAtomicBool =
    PrivateAllocationAtomicBool::new(false);

#[cfg(slime_private_fail_large_map)]
static FORCE_PRIVATE_LARGE_MAP_FAILURE: PrivateMapAtomicBool = PrivateMapAtomicBool::new(true);

/// Arm the one injected private-growth retype failure for the next transaction.
/// Set by the fixture service loop so the fault lands on a specific request
/// rather than on whichever growth in the boot happens to be first.
#[cfg(slime_private_fail_second_allocation)]
pub fn arm_private_second_allocation_failure() {
    FORCE_PRIVATE_SECOND_ALLOCATION_FAILURE.store(true, PrivateAllocationOrdering::Relaxed);
}

#[cfg(slime_private_fail_second_allocation)]
fn fail_private_allocation(kind: PrivateObjectKind, in_flight_granules: usize) -> bool {
    kind == PrivateObjectKind::Granule
        && in_flight_granules == 1
        && FORCE_PRIVATE_SECOND_ALLOCATION_FAILURE.swap(false, PrivateAllocationOrdering::Relaxed)
}

#[cfg(slime_private_fail_large_map)]
pub(crate) fn take_forced_private_large_map_failure() -> bool {
    FORCE_PRIVATE_LARGE_MAP_FAILURE.swap(false, PrivateMapOrdering::Relaxed)
}

#[cfg(slime_private_stress)]
static STRESS_SLOT_ATTEMPT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);

/// One-shot lifecycle injections. Each fails a real step of metadata growth
/// once, so the retained transaction, its retry, and the exactly-once release
/// are observed on the product path rather than modelled.
#[cfg(slime_metadata_lifecycle)]
pub(super) static INJECT_NODE_DELETE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(slime_metadata_lifecycle)]
static INJECT_LEDGER_RETAIN: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(slime_private_stress)]
pub(crate) fn stress_slot_pressure(attempt: usize) {
    STRESS_SLOT_ATTEMPT.store(attempt, core::sync::atomic::Ordering::Relaxed);
}

/// Untyped regions the root accepts from BootInfo, kernel and device each.
///
/// Derived from the kernel's own `MAX_NUM_BOOTINFO_UNTYPED_CAPS` rather than
/// chosen: that constant is the exact number of descriptors seL4 can place in
/// the boot info at all, so a table this size cannot be overrun by any kernel
/// the root is built against, and the `UntypedTableFull`/`DeviceTableFull`
/// refusals become unreachable-by-construction rather than a bound a new
/// machine can exceed. A fixed 64 was enough for the ARM and RISC-V reference
/// machines and is not enough for a q35 PC, which declares 78 device regions
/// for its ACPI, APIC, PCI ECAM, and firmware-reserved ranges.
///
/// Both roles share one bound because the kernel emits them into one list; the
/// two arrays stay separate because the root treats their authority differently.
pub const MAX_KERNEL_UNTYPEDS: usize = sel4::sel4_cfg_usize!(MAX_NUM_BOOTINFO_UNTYPED_CAPS);
pub const MAX_DEVICE_UNTYPEDS: usize = MAX_KERNEL_UNTYPEDS;
/// Maximum simultaneously owned task-backing records.
pub const MAX_TASK_ARENAS: usize = 48;
/// Root CSlots the kernel this root links against actually provides.
///
/// Read from the installed kernel configuration rather than declared here, so
/// a platform whose CNode width changes cannot leave a hand-written constant
/// describing the previous kernel.
const KERNEL_ROOT_CNODE_SLOTS: usize = 1 << sel4::sel4_cfg_usize!(ROOT_CNODE_SIZE_BITS);
/// Whether this image provisions descriptor storage for
/// [`MAX_PLANNED_PRIVATE_PAGES`] holders.
///
/// A threshold on the *initial* kernel CNode, not a capacity ceiling: both the
/// slot bitmap and every descriptor table grow from admitted ordinary memory,
/// and an allocation record names a full expanded address. What the threshold
/// still decides is how much record storage a boot provisions before any
/// workload runs. In this root, storage is capacity: the seL4 loader creates
/// one root CSlot per page of the root image, and the boot's own metadata
/// pages spend slots and ordinary bytes too. A kernel with a 12-bit initial
/// CNode — every physical board's default — has 4096 slots in total, so the
/// wide envelope would consume its CSpace before the product graph is
/// evaluated. Such an image keeps the narrow envelope, which still bounds
/// private backing well above the 512-page runtime ceiling
/// [`crate::private_memory::MAX_REGION_PAGES`] enforces.
const WIDE_TABLE_CNODE_SLOTS: usize = 1 << 19;
const LARGE_DESCRIPTOR_TABLES: bool = KERNEL_ROOT_CNODE_SLOTS >= WIDE_TABLE_CNODE_SLOTS;
/// Root-owned task allocation descriptors.
///
/// One descriptor per object or retained capability the root owns for a task.
/// Private planning counts every 4 KiB fallback frame, every leaf table, and a
/// retained large frame per 2 MiB span. The static envelope covers the largest
/// admitted image, translation tables, per-thread pages, TCBs, aliases, VSpace,
/// and CNode. A plan's fit is still decided by [`TaskBackingCapacity::fits`]
/// against live availability; this bound only ensures the table can represent
/// every simultaneously live task a budget this root admits can produce.
///
/// Derived from the *aggregate* ceiling and the task population, not from a
/// holder count: private descriptors are bounded by what every live region may
/// hold together, while the static cost is per task and every task pays it —
/// including the `init` and coordinator instances a holder graph also runs. A
/// bound sized as "N holders at the per-holder ceiling" leaves nothing for
/// them, and the shortfall surfaces as a spawn refused with
/// `DestinationSlotsExhausted` after the earlier holders have already reserved
/// their backing.
const MAX_PLANNED_PRIVATE_SPANS: usize =
    MAX_PLANNED_PRIVATE_PAGES.div_ceil(MAX_PRIVATE_EXTENT_PAGES);
// Frames are charged once against the aggregate image ceiling. Each task adds
// runtime objects and boundary translation tables; full image-table spans are
// bounded by the aggregate too, rather than multiplying the per-image ceiling.
const MAX_PLANNED_STATIC_ALLOCATIONS: usize =
    2 + 2 * (sel4::vspace_levels::NUM_LEVELS - 1) + 4 * crate::child_vspace::MAX_CHILD_THREADS;
const MAX_PLANNED_IMAGE_ALLOCATIONS: usize = crate::child_vspace::MAX_TOTAL_IMAGE_PAGES
    + (sel4::vspace_levels::NUM_LEVELS - 1)
        * crate::child_vspace::MAX_TOTAL_IMAGE_PAGES.div_ceil(512);
/// Private allocation descriptors every live region may demand together.
///
/// The aggregate page ceiling bounds the payload frames; each 2 MiB span adds a
/// leaf table and a retained large frame, and splitting the aggregate across
/// holders can leave one partial span per holder.
const fn max_admissible_private_allocations() -> usize {
    let total = crate::private_memory::MAX_TOTAL_PAGES;
    if total == 0 {
        return 0;
    }
    total + 2 * max_admissible_private_spans()
}
/// Private allocation descriptors the four-holder capacity *report* describes.
///
/// [`plan_task_backing`] represents up to [`MAX_PLANNED_PRIVATE_PAGES`] per
/// holder independently of the admitted runtime ceiling, and the capacity
/// qualification asks it about four such holders. The table must be able to
/// represent that plan or the report answers `fit=0` for a reason that is the
/// table's own size rather than the platform's resources.
const PLANNED_QUALIFICATION_HOLDERS: usize = 4;
const MAX_PLANNED_PRIVATE_ALLOCATIONS: usize =
    MAX_PLANNED_PRIVATE_PAGES + 2 * MAX_PLANNED_PRIVATE_SPANS;
/// The larger of the two demands, plus one static envelope per live task.
///
/// Both are real and neither dominates the other in general: the runtime
/// aggregate is what growth may actually charge, while the planner's
/// qualification is what the capacity report must be able to describe. The
/// static term is separate and per task, because every task pays it —
/// including the `init` and coordinator instances a holder graph also runs. A
/// bound sized as "N holders at the per-holder ceiling" leaves nothing for
/// them, and the shortfall surfaces as a spawn refused with
/// `DestinationSlotsExhausted` after the earlier holders reserved their
/// backing.
const fn widest_private_allocations() -> usize {
    let runtime = max_admissible_private_allocations();
    let planned = PLANNED_QUALIFICATION_HOLDERS * MAX_PLANNED_PRIVATE_ALLOCATIONS;
    if runtime > planned { runtime } else { planned }
}
pub const MAX_TASK_ALLOCATIONS: usize = if LARGE_DESCRIPTOR_TABLES {
    widest_private_allocations()
        + MAX_PLANNED_IMAGE_ALLOCATIONS
        + MAX_TASK_ARENAS * MAX_PLANNED_STATIC_ALLOCATIONS
        + mapping_tables::RECORDS
} else {
    4096 + mapping_tables::RECORDS
};
const _: () = assert!(
    MAX_TASK_ALLOCATIONS
        >= widest_private_allocations()
            + PLANNED_QUALIFICATION_HOLDERS * MAX_PLANNED_STATIC_ALLOCATIONS
        || !LARGE_DESCRIPTOR_TABLES,
    "allocation table cannot hold the widest admitted private population \
     alongside the static backing of every task the qualification stages"
);
/// Widest private-extent population any admitted budget can demand.
///
/// Every nonzero holder consumes one data and one table extent per 2 MiB span.
/// Splitting the aggregate across holders can add at most one partial span per
/// holder, so this computes the exact worst distribution without growing the
/// descriptor tables of conservative 12-bit-CNode board images.
const fn max_admissible_private_spans() -> usize {
    let total = crate::private_memory::MAX_TOTAL_PAGES;
    if total == 0 {
        return 0;
    }
    let holders = if boot_contracts::private_memory_budget::MAX_HOLDERS < total {
        boot_contracts::private_memory_budget::MAX_HOLDERS
    } else {
        total
    };
    total.div_ceil(MAX_PRIVATE_EXTENT_PAGES) + holders - 1
}

const fn max_admissible_private_extents() -> usize {
    2 * max_admissible_private_spans()
}

/// The widest extent population either demand produces.
///
/// The same two-sided bound as [`widest_private_allocations`]: the runtime
/// aggregate is what growth may charge, while the four-holder capacity report
/// asks the planner about [`MAX_PLANNED_PRIVATE_PAGES`] per holder, which needs
/// one data and one table extent per 2 MiB span.
const fn widest_private_extents() -> usize {
    let runtime = max_admissible_private_extents();
    let planned = PLANNED_QUALIFICATION_HOLDERS * 2 * MAX_PLANNED_PRIVATE_SPANS;
    if runtime > planned { runtime } else { planned }
}

/// Every task consumes one static extent; qualified images additionally carry
/// the widest private extent population either demand produces.
pub const MAX_TASK_EXTENTS: usize = if LARGE_DESCRIPTOR_TABLES {
    MAX_TASK_ARENAS + widest_private_extents() + mapping_tables::RECORDS
} else {
    3 * MAX_TASK_ARENAS + mapping_tables::RECORDS
};
const _: () = assert!(
    MAX_TASK_EXTENTS >= MAX_TASK_ARENAS + max_admissible_private_extents(),
    "extent table cannot hold the widest admitted private-extent population"
);

const GRANULE_BYTES: usize = 4096;
/// Largest independently reclaimable private-data extent.
const MAX_PRIVATE_EXTENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PRIVATE_EXTENT_PAGES: usize = MAX_PRIVATE_EXTENT_BYTES / GRANULE_BYTES;
/// Largest quota the host planner can represent. Independent of the public
/// runtime ceiling, which `PrivateBackingLayout::for_quota` clamps separately.
pub const MAX_PLANNED_PRIVATE_PAGES: usize = 256 * 1024 * 1024 / GRANULE_BYTES;
/// Maximum queue pages allocated as one physically contiguous run.
const MAX_CONTIGUOUS_GRANULES: usize = 64;
/// Maximum objects in one seL4 untyped retype invocation.
const MAX_RETYPE_FAN_OUT: usize = 256;

fn device_retype_plan(
    retyped: usize,
    target: usize,
    free_slots: usize,
    holding_anchor: bool,
) -> Option<(usize, usize)> {
    let remaining = target.checked_sub(retyped)?.checked_add(1)?;
    let available = free_slots.saturating_sub(usize::from(holding_anchor));
    let batch = core::cmp::min(remaining, core::cmp::min(available, MAX_RETYPE_FAN_OUT));
    (batch != 0).then_some((remaining.div_ceil(MAX_RETYPE_FAN_OUT), batch))
}

/// Root CSlots whose allocation-time physical base is retained at once.
///
/// This bounds the **DMA-participating frame population, not the CSpace**.
/// Only a granule retyped from ordinary RAM, or an MMIO page retyped from a
/// device untyped, can be handed to a device, so only those need a physical
/// base remembered. The root holds at most: one frame-cap anchor per page of
/// every live shared buffer, IO1's contiguous device-queue pages, one frame per
/// declared MMIO region the probe reaches and per mapping IO1 hands out, the
/// userspace IO service's declared DMA and MMIO ceilings, and — only in the
/// immutable selector image — two bootstrap DMA pages per admitted boot device.
/// Every term is another module's own declared ceiling rather than a number
/// chosen here, so a plane that raises its bound raises this with it instead of
/// silently overrunning it.
///
/// The live bound is 448 entries, or 452 in the immutable selector image,
/// whose two bootstrap DMA pages per admitted boot device are the only terms
/// this product path no longer contributes. [`PROVENANCE_SLOTS`] rounds either
/// to a 1024-position open table of two-word records: 16 KiB of `.bss`, or four
/// root-image pages and their corresponding root CSlots.
#[cfg(slime_boot_selector)]
const SELECTOR_PHYSICAL_PROVENANCE: usize = 2 * crate::device::MAX_BLOCK_DEVICES;
#[cfg(not(slime_boot_selector))]
const SELECTOR_PHYSICAL_PROVENANCE: usize = 0;

const MAX_PHYSICAL_PROVENANCE: usize = crate::shared_buffer::MAX_FRAME_ANCHORS
    + crate::io_resource::MAX_DMA_MAPPINGS
    + crate::io_resource::MAX_MMIO_REGIONS
    + crate::io_resource::MAX_MMIO_MAPPINGS
    + SELECTOR_PHYSICAL_PROVENANCE;

/// Positions in the open-addressed provenance table.
///
/// A power of two so the probe start is a mask rather than a division, and
/// twice the live bound so the table never runs at a load factor that turns
/// linear probing into a scan. Never equal to the live bound: [`insert`]'s
/// walk to a free position relies on at least one entry always being empty.
///
/// [`insert`]: ProvenanceTable::insert
const PROVENANCE_SLOTS: usize = (2 * MAX_PHYSICAL_PROVENANCE).next_power_of_two();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocError {
    NoKernelUntyped,
    AdaptiveFunding {
        resource: &'static str,
        required: u64,
        available: u64,
    },
    UntypedTableFull {
        limit: usize,
        declared: usize,
    },
    SlotsExhausted {
        allocated: usize,
    },
    SlotRangeTooLarge {
        declared: usize,
        limit: usize,
    },
    UntypedExhausted {
        size_bits: usize,
        remaining: usize,
    },
    Retype {
        size_bits: usize,
        error: sel4::Error,
    },
    DeviceTableFull {
        limit: usize,
        declared: usize,
    },
    NoDeviceUntyped {
        paddr: usize,
    },
    UnalignedDeviceFrame {
        paddr: usize,
    },
    DeviceFramePassed {
        paddr: usize,
    },
    DeviceCleanup {
        slot: usize,
        error: sel4::Error,
    },
    ArenaTableFull {
        limit: usize,
    },
    ArenaTooSmall {
        size_bits: usize,
        required: usize,
    },
    ArenaSlotTableFull {
        limit: usize,
    },
    UnknownArena(TaskArenaId),
    ArenaCleanup {
        slot: usize,
        error: sel4::Error,
    },
    /// The physical-provenance table has no free position for a frame this
    /// allocation just retyped.
    ///
    /// Fails the allocation rather than losing the record. A frame whose
    /// physical base the root cannot recover would be mapped into a device's
    /// descriptor with a *wrong* address, which is worse than not existing:
    /// the device would read or write memory nothing granted it.
    ProvenanceTableFull {
        limit: usize,
    },
    /// A private window needs more 2 MiB spans than one span-ownership record
    /// addresses.
    ///
    /// An addressing limit of the tracking storage, not a capacity the image
    /// reserves: it refuses the window outright rather than tracking part of
    /// it, because a span whose table ownership is untracked would be priced
    /// as empty and take a second table over the same address.
    PrivateRegionSpans {
        spans: usize,
        limit: usize,
    },
    /// A private window is malformed: empty, misaligned, or ending past the
    /// last address. Refused before the window exists, because every later
    /// page address is derived from it unchecked.
    PrivateRegionWindow {
        base: usize,
        reservation: usize,
    },
}

impl AllocError {
    /// The allocator resource this error names, in a refusal report's words.
    pub const fn resource(self) -> &'static str {
        match self {
            Self::AdaptiveFunding { resource, .. } => resource,
            Self::NoKernelUntyped | Self::UntypedExhausted { .. } => "ordinary-layout",
            Self::UntypedTableFull { .. } => "retained-prefix-records",
            Self::SlotsExhausted { .. } | Self::SlotRangeTooLarge { .. } => "root-cslots",
            Self::Retype { .. } => "retype",
            Self::ArenaTableFull { .. } => "extent-records",
            Self::ArenaSlotTableFull { .. } => "allocation-descriptors",
            Self::ArenaTooSmall { .. } => "arena-extent",
            Self::ArenaCleanup { .. } => "cleanup",
            _ => "acquisition",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UntypedRegion {
    cap: sel4::cap::Untyped,
    paddr: usize,
    size_bits: usize,
    watermark: usize,
}

impl UntypedRegion {
    fn capacity(&self) -> usize {
        1usize << self.size_bits
    }
    fn remaining(&self) -> usize {
        self.capacity().saturating_sub(self.watermark)
    }
}

/// One ordinary (non-device) BootInfo untyped range, as the root admitted it.
///
/// The aggregate `SLIME_ROOT allocator bytes=` marker cannot answer whether a
/// platform actually gained RAM: a kernel described with a smaller physical
/// window reports fewer, smaller regions while the launcher's `-m` is
/// unchanged, and one summed byte count hides which range the bytes came from.
/// Per-range physical bases are what distinguish a kernel-visible platform
/// raise from a larger emulator argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryRange {
    /// Physical base seL4 reported for this untyped.
    pub paddr: usize,
    /// Its size, as `1 << size_bits`.
    pub bytes: usize,
    /// Bytes already consumed by the root's monotonic watermark.
    pub used: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeviceRegion {
    cap: sel4::cap::Untyped,
    paddr: usize,
    size_bits: usize,
    retyped: usize,
}

impl DeviceRegion {
    fn contains(&self, paddr: usize, len: usize) -> bool {
        let Some(end) = paddr.checked_add(len) else {
            return false;
        };
        let Some(region_end) = self.paddr.checked_add(1usize << self.size_bits) else {
            return false;
        };
        paddr >= self.paddr && end <= region_end
    }
}

/// Where an object lands under seL4's object-size alignment rule.
pub(crate) fn plan_allocation(
    watermark: usize,
    capacity: usize,
    size_bits: usize,
) -> Option<(usize, usize)> {
    let size = 1usize.checked_shl(u32::try_from(size_bits).ok()?)?;
    let start = watermark.checked_next_multiple_of(size)?;
    let end = start.checked_add(size)?;
    (end <= capacity).then_some((start, end))
}

fn task_backing_extents_fit_in(
    regions: &mut [Option<UntypedRegion>],
    plan: TaskBackingPlan,
    static_backing: TaskStaticBacking,
    holders: usize,
) -> bool {
    let Some(static_size_bits) = static_backing
        .reserved_bytes
        .is_power_of_two()
        .then(|| static_backing.reserved_bytes.trailing_zeros() as usize)
    else {
        return holders == 0;
    };
    let layout = PrivateBackingLayout::for_pages(plan.private_pages);
    let expected_table_bytes = layout.spans.checked_mul(GRANULE_BYTES);
    let expected_reserved_bytes = layout
        .spans
        .checked_mul(MAX_PRIVATE_EXTENT_BYTES)
        .and_then(|bytes| bytes.checked_add(expected_table_bytes?));
    if layout.spans != plan.data_extents
        || expected_table_bytes != Some(plan.page_table_bytes)
        || expected_reserved_bytes != Some(plan.reserved_bytes)
        || 1usize.checked_add(layout.extent_parent_slots()) != Some(plan.extent_descriptors)
    {
        return false;
    }
    let mut entries = [None; global_backing::MAX_PRESERVED];
    let mut entries_len = 0;
    let mut preserved = preserved::SliceRecords {
        entries: &mut entries,
        len: &mut entries_len,
    };
    let mut slots = usize::MAX;
    for _ in 0..holders {
        if !global_backing::plan_extent(regions, &mut preserved, &mut slots, static_size_bits) {
            return false;
        }
        let mut index = 0;
        while let Some(extent) = layout.extent(index) {
            if !global_backing::plan_extent(regions, &mut preserved, &mut slots, extent.size_bits) {
                return false;
            }
            index += 1;
        }
    }
    true
}

/// Pure task-arena sizing model, shared by admission and host tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArenaPlan {
    watermark: usize,
    allocations: usize,
}

impl ArenaPlan {
    pub const fn new() -> Self {
        Self {
            watermark: 0,
            allocations: 0,
        }
    }

    pub fn add_size_bits(&mut self, size_bits: usize) -> Option<()> {
        let size = 1usize.checked_shl(u32::try_from(size_bits).ok()?)?;
        let start = self.watermark.checked_next_multiple_of(size)?;
        self.watermark = start.checked_add(size)?;
        self.allocations = self.allocations.checked_add(1)?;
        Some(())
    }

    pub fn add(&mut self, blueprint: sel4::ObjectBlueprint) -> Option<()> {
        self.add_size_bits(blueprint.physical_size_bits())
    }

    pub const fn required_bytes(self) -> usize {
        self.watermark
    }
    pub const fn allocation_count(self) -> usize {
        self.allocations
    }

    /// Extend this plan to an already computed worst-case watermark.
    ///
    /// Alternative allocation sequences cannot both be replayed into one bump
    /// plan. Their maximum end offset is the exact reservation the arena must
    /// cover, so callers model each sequence on a copy and retain the larger.
    pub fn reserve_to(&mut self, watermark: usize) {
        self.watermark = self.watermark.max(watermark);
    }
    pub fn required_size_bits(self) -> Option<usize> {
        let bytes = self.watermark.max(1);
        Some(usize::BITS as usize - bytes.saturating_sub(1).leading_zeros() as usize)
    }
}
/// Capacity report for a quota-backed task without allocating kernel objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskBackingPlan {
    pub private_pages: usize,
    pub data_extents: usize,
    pub extent_descriptors: usize,
    pub allocation_descriptors: usize,
    pub required_cslots: usize,
    pub reserved_bytes: usize,
    pub payload_bytes: usize,
    pub page_table_bytes: usize,
    pub alignment_waste: usize,
}

/// Static arena cost already materialized for one exemplar task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskStaticBacking {
    pub allocation_descriptors: usize,
    pub reserved_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskBackingRequirements {
    pub cslots: usize,
    pub allocation_descriptors: usize,
    pub extent_descriptors: usize,
    pub reserved_bytes: usize,
}

/// Why live resources cannot place a planned task's private backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutLimit {
    /// Retained-prefix metadata could not be funded from ordinary memory.
    MetadataRecords,
    /// Root CSpace could not name enough slots, even after growing a leaf.
    RootSlots,
    /// No admitted ordinary range can place an extent at its alignment.
    Placement,
}

/// Hypothetical holder capacity against the root's current live resource state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskBackingCapacity {
    pub plan: TaskBackingPlan,
    pub static_backing: TaskStaticBacking,
    pub holders: usize,
    pub cslots_available: usize,
    pub allocation_descriptors_available: usize,
    pub extent_descriptors_available: usize,
    pub ordinary_bytes_available: usize,
    pub ordinary_layout: Result<(), LayoutLimit>,
    pub root_image_bytes: usize,
    pub root_stack_bytes: usize,
    pub root_heap_bytes: usize,
}

impl TaskBackingCapacity {
    pub fn requirements(self) -> Option<TaskBackingRequirements> {
        if self.holders == 0 {
            return Some(TaskBackingRequirements {
                cslots: 0,
                allocation_descriptors: 0,
                extent_descriptors: 0,
                reserved_bytes: 0,
            });
        }
        Some(TaskBackingRequirements {
            cslots: self
                .plan
                .required_cslots
                .checked_add(self.static_backing.allocation_descriptors)?
                .checked_mul(self.holders)?,
            allocation_descriptors: self
                .plan
                .allocation_descriptors
                .checked_add(self.static_backing.allocation_descriptors)?
                .checked_mul(self.holders)?,
            extent_descriptors: self.plan.extent_descriptors.checked_mul(self.holders)?,
            reserved_bytes: self
                .plan
                .reserved_bytes
                .checked_add(self.static_backing.reserved_bytes)?
                .checked_mul(self.holders)?,
        })
    }

    /// The resource that refuses the admitted holders, or `None` when they all
    /// fit. A refusal names what actually ran out on this platform, so no
    /// compile-time table size can be read as the product's capacity.
    pub fn limiting_resource(self) -> Option<&'static str> {
        let Some(required) = self.requirements() else {
            return Some("arithmetic");
        };
        if required.allocation_descriptors > self.allocation_descriptors_available {
            return Some("allocation-descriptors");
        }
        if required.extent_descriptors > self.extent_descriptors_available {
            return Some("extent-descriptors");
        }
        if required.cslots > self.cslots_available {
            return Some("root-cslots");
        }
        if required.reserved_bytes > self.ordinary_bytes_available {
            return Some("ordinary-bytes");
        }
        match self.ordinary_layout {
            Ok(()) => None,
            Err(LayoutLimit::MetadataRecords) => Some("metadata-records"),
            Err(LayoutLimit::RootSlots) => Some("root-cslots"),
            Err(LayoutLimit::Placement) => Some("ordinary-layout"),
        }
    }

    pub fn fits(self) -> bool {
        self.limiting_resource().is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateExtentSpec {
    kind: ExtentKind,
    size_bits: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrivateBackingLayout {
    private_pages: usize,
    spans: usize,
    pub(crate) allocation_descriptors: usize,
}

impl PrivateBackingLayout {
    /// Root CSlots retained for the data and table parent untypeds.
    pub(crate) const fn extent_parent_slots(&self) -> usize {
        2 * self.spans
    }

    fn for_pages(private_pages: usize) -> Self {
        let spans = private_pages.div_ceil(MAX_PRIVATE_EXTENT_PAGES);
        Self {
            private_pages,
            spans,
            allocation_descriptors: private_pages + 2 * spans,
        }
    }

    pub(crate) fn for_quota(quota: usize) -> Self {
        Self::for_pages(quota.min(crate::private_memory::MAX_REGION_PAGES))
    }

    fn extent(self, index: usize) -> Option<PrivateExtentSpec> {
        if index >= self.extent_parent_slots() {
            return None;
        }
        // Group leaf-table extents before data extents so alternating 4 KiB
        // and 2 MiB retypes cannot strand almost 2 MiB at every span boundary.
        Some(if index < self.spans {
            PrivateExtentSpec {
                kind: ExtentKind::PrivateTables,
                size_bits: GRANULE_BYTES.trailing_zeros() as usize,
            }
        } else {
            PrivateExtentSpec {
                kind: ExtentKind::PrivateData,
                size_bits: MAX_PRIVATE_EXTENT_BYTES.trailing_zeros() as usize,
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateBackingRequest {
    Extent { kind: ExtentKind, size_bits: usize },
    Slots { count: usize },
}

fn provision_private_backing_with(
    quota: usize,
    mut apply: impl FnMut(PrivateBackingRequest) -> Result<(), AllocError>,
) -> Result<(), AllocError> {
    let layout = PrivateBackingLayout::for_quota(quota);
    let mut index = 0;
    while let Some(extent) = layout.extent(index) {
        apply(PrivateBackingRequest::Extent {
            kind: extent.kind,
            size_bits: extent.size_bits,
        })?;
        index += 1;
    }
    apply(PrivateBackingRequest::Slots {
        count: layout.allocation_descriptors,
    })
}

/// Plan the same segmented private backing used by runtime provisioning.
pub fn plan_task_backing(private_pages: usize) -> Option<TaskBackingPlan> {
    if private_pages > MAX_PLANNED_PRIVATE_PAGES {
        return None;
    }
    let spans = private_pages.div_ceil(MAX_PRIVATE_EXTENT_PAGES);
    let data_extents = spans;
    let leaf_tables = spans;
    let large_frames = spans;
    let allocation_descriptors = private_pages
        .checked_add(leaf_tables)?
        .checked_add(large_frames)?;
    let extent_descriptors = 1usize.checked_add(data_extents)?.checked_add(leaf_tables)?;
    let payload_bytes = private_pages.checked_mul(GRANULE_BYTES)?;
    let page_table_bytes = leaf_tables.checked_mul(GRANULE_BYTES)?;
    let reserved_data = data_extents.checked_mul(MAX_PRIVATE_EXTENT_BYTES)?;
    let reserved_bytes = reserved_data.checked_add(page_table_bytes)?;
    Some(TaskBackingPlan {
        private_pages,
        data_extents,
        extent_descriptors,
        allocation_descriptors,
        required_cslots: allocation_descriptors.checked_add(extent_descriptors)?,
        reserved_bytes,
        payload_bytes,
        page_table_bytes,
        alignment_waste: reserved_data.checked_sub(payload_bytes)?,
    })
}

impl Default for ArenaPlan {
    fn default() -> Self {
        Self::new()
    }
}

/// One live root CSlot's allocation-time physical base.
///
/// `slot` doubles as the occupancy flag. [`ProvenanceTable::EMPTY`] is
/// `usize::MAX`, which no root CSlot address can be — the expanded namespace
/// stops one leaf below it — so the sentinel costs no discriminant word, and
/// the record stays two words rather than the three an `Option` would take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProvenanceEntry {
    slot: usize,
    paddr: usize,
}

/// Allocation-time physical provenance for the frames a device may be handed.
///
/// Open-addressed on the root CSlot index with linear probing, sized by
/// [`MAX_PHYSICAL_PROVENANCE`] rather than by the CSpace. Deletion shifts the
/// probe chain back rather than leaving a tombstone, so a root that allocates
/// and releases DMA frames indefinitely never degrades: the table's cost is its
/// live population, not its history.
struct ProvenanceTable {
    entries: [ProvenanceEntry; PROVENANCE_SLOTS],
    len: usize,
}

impl ProvenanceTable {
    const EMPTY: usize = usize::MAX;
    const MASK: usize = PROVENANCE_SLOTS - 1;

    const fn new() -> Self {
        Self {
            entries: [ProvenanceEntry {
                slot: Self::EMPTY,
                paddr: 0,
            }; PROVENANCE_SLOTS],
            len: 0,
        }
    }

    const fn home(slot: usize) -> usize {
        slot & Self::MASK
    }

    const fn step(probe: usize) -> usize {
        (probe + 1) & Self::MASK
    }

    /// Cyclic probe distance from a chain's start to one of its positions.
    const fn distance(home: usize, probe: usize) -> usize {
        probe.wrapping_sub(home) & Self::MASK
    }

    fn position(&self, slot: usize) -> Option<usize> {
        let mut probe = Self::home(slot);
        // Bounded by the table rather than by reaching an empty position, so a
        // corrupted chain is a miss instead of a hang.
        for _ in 0..PROVENANCE_SLOTS {
            let entry = self.entries[probe];
            if entry.slot == Self::EMPTY {
                return None;
            }
            if entry.slot == slot {
                return Some(probe);
            }
            probe = Self::step(probe);
        }
        None
    }

    fn get(&self, slot: usize) -> Option<usize> {
        self.position(slot).map(|probe| self.entries[probe].paddr)
    }

    /// Record `slot`'s physical base, or refuse when the table is at its bound.
    ///
    /// Refusing is the whole point: a frame whose physical address the root
    /// cannot recover must fail its allocation, never reach a device descriptor
    /// carrying some other frame's address. Re-recording a slot already present
    /// overwrites in place and cannot fail, so a slot the pool reissued after a
    /// release that did not reach here still ends up with its current base.
    fn insert(&mut self, slot: usize, paddr: usize) -> Result<(), AllocError> {
        let mut probe = Self::home(slot);
        // Terminates: `len <= MAX_PHYSICAL_PROVENANCE < PROVENANCE_SLOTS`, so
        // some position is always empty.
        loop {
            let entry = self.entries[probe];
            if entry.slot == Self::EMPTY {
                break;
            }
            if entry.slot == slot {
                self.entries[probe].paddr = paddr;
                return Ok(());
            }
            probe = Self::step(probe);
        }
        if self.len >= MAX_PHYSICAL_PROVENANCE {
            return Err(AllocError::ProvenanceTableFull {
                limit: MAX_PHYSICAL_PROVENANCE,
            });
        }
        self.entries[probe] = ProvenanceEntry { slot, paddr };
        self.len += 1;
        Ok(())
    }

    /// Forget `slot`'s physical base, reporting whether one was held.
    ///
    /// The vacated position is closed by pulling back every following entry
    /// whose own chain runs through it, which keeps [`Self::position`]'s
    /// stop-at-empty walk correct without tombstones.
    fn remove(&mut self, slot: usize) -> bool {
        let Some(mut hole) = self.position(slot) else {
            return false;
        };
        self.entries[hole].slot = Self::EMPTY;
        self.len -= 1;
        let mut probe = Self::step(hole);
        loop {
            let entry = self.entries[probe];
            if entry.slot == Self::EMPTY {
                return true;
            }
            let home = Self::home(entry.slot);
            // Movable exactly when a walk from this entry's own chain start
            // reaches the hole before it reaches the entry: then filling the
            // hole keeps the entry findable, and leaving it would strand it
            // behind the empty position.
            if Self::distance(home, hole) < Self::distance(home, probe) {
                self.entries[hole] = entry;
                self.entries[probe].slot = Self::EMPTY;
                hole = probe;
            }
            probe = Self::step(probe);
        }
    }
}

/// Whether an object of this shape can be handed to a device, and therefore
/// needs its physical base retained.
///
/// A base page of ordinary RAM and nothing else: a TCB, endpoint, CNode or
/// translation table has no physical identity any caller of
/// [`ObjectAllocator::physical_address_of`] can use, and admitting them would
/// spend the bounded table on records no one reads — which would then refuse a
/// frame that genuinely needed one.
fn records_provenance(blueprint: sel4::ObjectBlueprint) -> bool {
    blueprint == <sel4::cap_type::Granule as sel4::CapTypeForObjectOfFixedSize>::object_blueprint()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskArenaId {
    index: u16,
    serial: u32,
}

impl TaskArenaId {
    pub const fn index(self) -> usize {
        self.index as usize
    }
    pub(crate) const fn from_raw(index: u16, serial: u32) -> Self {
        Self { index, serial }
    }
}

/// Which backing one private allocation may be retyped from.
///
/// Passed down from the growth plan rather than decided here, so a page the
/// transaction priced and certified against reservation-owned backing cannot
/// be served from the common pool, and a pooled page cannot quietly spend a
/// guarantee. Selection without this is best-fit over everything the arena
/// owns, which would mix the two.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExtentSource {
    #[default]
    Common,
    Guaranteed(guarantee_vault::ReservationId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateObjectKind {
    Empty = 0,
    Granule = 1,
    LargeFrame = 2,
    LeafTable = 3,
}

const PRIVATE_STATE_NONE: u32 = u32::MAX;
const PRIVATE_EXTENT_NONE: u32 = u32::MAX;

pub(crate) struct PrivateAllocation {
    arena: TaskArenaId,
    position: u32,
    cap: sel4::cap::Unspecified,
    mapped: bool,
}

impl PrivateAllocation {
    pub(crate) const fn cap(&self) -> sel4::cap::Unspecified {
        self.cap
    }

    pub(crate) const fn mapped(&self) -> bool {
        self.mapped
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArenaAllocation {
    address: usize,
    state: u32,
}

impl ArenaAllocation {
    const EMPTY: Self = Self {
        address: usize::MAX,
        state: u32::MAX,
    };
    const SIZE_SHIFT: u32 = 0;
    const SIZE_MASK: u32 = 0x3f << Self::SIZE_SHIFT;
    const PRIVATE: u32 = 1 << 25;
    const REUSABLE: u32 = 1 << 26;
    const KIND_SHIFT: u32 = 27;
    const KIND_MASK: u32 = 0x3 << Self::KIND_SHIFT;
    const MAPPED: u32 = 1 << 29;
    const IN_FLIGHT: u32 = 1 << 30;

    fn new(slot: usize, size_bits: usize, private: bool, reusable: bool) -> Self {
        assert!(size_bits < 64);
        Self {
            address: slot,
            state: (size_bits as u32) << Self::SIZE_SHIFT
                | if private { Self::PRIVATE } else { 0 }
                | if reusable { Self::REUSABLE } else { 0 },
        }
    }

    const fn slot(self) -> usize {
        self.address
    }

    const fn size_bits(self) -> usize {
        ((self.state & Self::SIZE_MASK) >> Self::SIZE_SHIFT) as usize
    }

    const fn is_private(self) -> bool {
        self.state & Self::PRIVATE != 0
    }

    const fn is_reusable(self) -> bool {
        self.state & Self::REUSABLE != 0
    }

    const fn private_kind(self) -> PrivateObjectKind {
        match (self.state & Self::KIND_MASK) >> Self::KIND_SHIFT {
            1 => PrivateObjectKind::Granule,
            2 => PrivateObjectKind::LargeFrame,
            3 => PrivateObjectKind::LeafTable,
            _ => PrivateObjectKind::Empty,
        }
    }

    const fn is_mapped(self) -> bool {
        self.state & Self::MAPPED != 0
    }

    const fn is_in_flight(self) -> bool {
        self.state & Self::IN_FLIGHT != 0
    }

    fn set_in_flight(&mut self, in_flight: bool) {
        if in_flight {
            self.state |= Self::IN_FLIGHT;
        } else {
            self.state &= !Self::IN_FLIGHT;
        }
    }

    fn set_private_state(
        &mut self,
        kind: PrivateObjectKind,
        size_bits: usize,
        reusable: bool,
        mapped: bool,
    ) {
        self.state = (self.state
            & !(Self::SIZE_MASK
                | Self::KIND_MASK
                | Self::REUSABLE
                | Self::MAPPED
                | Self::IN_FLIGHT))
            | (size_bits as u32) << Self::SIZE_SHIFT
            | (kind as u32) << Self::KIND_SHIFT
            | if reusable { Self::REUSABLE } else { 0 }
            | if mapped { Self::MAPPED } else { 0 };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtentKind {
    Static,
    PrivateData,
    PrivateTables,
    MappingTables,
    /// A returned extent adopted whole as an infrastructure source. Held for
    /// the root's lifetime, like every other infrastructure source.
    Infrastructure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExtentRecord {
    parent: sel4::cap::Untyped,
    /// Physical base of the retype that created this extent.
    ///
    /// Retained for the lifetime of the record, including while it is
    /// reusable: a returned extent keeps the bytes it always had, and an
    /// elastic transaction certifies its placements against the physical
    /// range it will actually occupy rather than against a predicted one.
    paddr: usize,
    size_bits: usize,
    owner: u16,
    serial: u32,
    kind: ExtentKind,
    active: bool,
    revoked: bool,
    watermark: usize,
    /// Live objects retyped from this extent. 32 bits leave room for `link`
    /// without growing the record, which would change how many records a
    /// metadata page holds.
    objects: u32,
    bytes: usize,
    /// Reservation that owns this record across borrows, or
    /// [`guarantee_vault::RESERVATION_NONE`].
    ///
    /// Retained while a task arena holds the extent. That retention is the
    /// whole of borrow/return: every existing release path already clears
    /// `active` only after its revoke succeeded, so a returned extent lands
    /// back in the reservation it was taken from rather than in common
    /// capacity, and a failed revoke leaves it owned and unavailable.
    origin: u32,
    /// Two half-size children now own this record's bytes; see
    /// [`extent_buddy`]. A split record is neither free nor active until both
    /// children are free again and its revoke merges them.
    split: bool,
    /// The two children of a split record, or [`extent_buddy::NO_EXTENT`].
    children: [u32; 2],
    /// The next extent on its arena's room chain, or
    /// [`record_tables::NO_LINK`]. Written only by the extent table.
    link: u32,
}

impl ExtentRecord {
    fn new(parent: sel4::cap::Untyped, size_bits: usize) -> Self {
        Self {
            parent,
            paddr: 0,
            size_bits,
            owner: u16::MAX,
            serial: 0,
            kind: ExtentKind::Static,
            active: false,
            revoked: false,
            watermark: 0,
            objects: 0,
            bytes: 0,
            origin: guarantee_vault::RESERVATION_NONE,
            split: false,
            children: [extent_buddy::NO_EXTENT; 2],
            link: record_tables::NO_LINK,
        }
    }

    /// Hand this record to one task arena.
    ///
    /// `origin` is deliberately untouched: a record taken from common capacity
    /// has none, and a record borrowed from a reservation must keep it so the
    /// return path knows where the backing belongs.
    fn assign(&mut self, owner: usize, serial: u32, kind: ExtentKind) {
        self.owner = owner as u16;
        self.serial = serial;
        self.kind = kind;
        self.active = true;
        self.revoked = false;
        self.watermark = 0;
        self.objects = 0;
        self.bytes = 0;
    }

    /// Take this record out of common capacity for one reservation.
    ///
    /// A reserved record stays inactive and owned by no task arena: `active`
    /// keeps meaning "held by a live arena", and reservation ownership is the
    /// separate fact every selection path tests through [`Self::is_reserved`].
    fn reserve(&mut self, reservation: usize, kind: ExtentKind) {
        self.owner = u16::MAX;
        self.serial = 0;
        self.kind = kind;
        self.active = false;
        self.revoked = false;
        self.watermark = 0;
        self.objects = 0;
        self.bytes = 0;
        self.origin = reservation as u32;
    }

    /// Publish this record back as common capacity.
    fn unreserve(&mut self) {
        self.origin = guarantee_vault::RESERVATION_NONE;
    }

    /// Whether a reservation owns this record and no arena holds it.
    ///
    /// The one predicate ordinary and elastic paths consult, directly or
    /// through [`Self::is_common_free`]. A record it answers `true` for is
    /// invisible to arena ownership, reusable-chain rebuild, best-fit
    /// selection, extent reuse and free-capacity reporting.
    const fn is_reserved(&self) -> bool {
        self.origin != guarantee_vault::RESERVATION_NONE && !self.active
    }

    /// Whether a task arena currently holds backing a reservation owns.
    const fn is_borrowed(&self) -> bool {
        self.origin != guarantee_vault::RESERVATION_NONE && self.active
    }

    const fn owned_by_reservation(&self, reservation: usize) -> bool {
        self.origin == reservation as u32 && self.origin != guarantee_vault::RESERVATION_NONE
    }

    const fn reserved_by(&self, reservation: usize) -> bool {
        self.is_reserved() && self.owned_by_reservation(reservation)
    }

    /// Whether this record is capacity the next ordinary or elastic request
    /// may take: no live arena holds it and no reservation owns it.
    const fn is_common_free(&self) -> bool {
        !self.active && !self.split && self.origin == guarantee_vault::RESERVATION_NONE
    }

    const fn belongs_to(&self, id: TaskArenaId) -> bool {
        self.active && self.owner as usize == id.index() && self.serial == id.serial
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AllocationRecord {
    owner: u16,
    extent: u32,
    serial: u32,
    allocation: ArenaAllocation,
    next_state: u32,
}

impl AllocationRecord {
    const EMPTY: Self = Self {
        owner: u16::MAX,
        extent: PRIVATE_EXTENT_NONE,
        serial: 0,
        allocation: ArenaAllocation::EMPTY,
        next_state: PRIVATE_STATE_NONE,
    };

    const fn belongs_to(&self, id: TaskArenaId) -> bool {
        self.owner as usize == id.index() && self.serial == id.serial
    }
}

fn task_static_backing_from_records<'a>(
    id: TaskArenaId,
    allocations: impl Iterator<Item = &'a AllocationRecord>,
    extents: impl Iterator<Item = &'a Option<ExtentRecord>>,
) -> Option<TaskStaticBacking> {
    let allocation_descriptors = allocations
        .filter(|record| record.belongs_to(id) && !record.allocation.is_private())
        .count();
    let mut matching = extents.flatten().filter(|extent| {
        extent.belongs_to(id) && extent.kind == ExtentKind::Static && !extent.revoked
    });
    let extent = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    Some(TaskStaticBacking {
        allocation_descriptors,
        reserved_bytes: 1usize.checked_shl(u32::try_from(extent.size_bits).ok()?)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArenaRecord {
    serial: u32,
    active: bool,
    slot_len: usize,
    reusable_heads: [u32; 4],
    in_flight_head: u32,
    in_flight_granules: usize,
    releasing: bool,
}

impl ArenaRecord {
    const fn empty() -> Self {
        Self {
            serial: 0,
            active: false,
            slot_len: 0,
            reusable_heads: [PRIVATE_STATE_NONE; 4],
            in_flight_head: PRIVATE_STATE_NONE,
            in_flight_granules: 0,
            releasing: false,
        }
    }

    const fn id(&self, index: usize) -> TaskArenaId {
        TaskArenaId {
            index: index as u16,
            serial: self.serial,
        }
    }
}

const _: () = assert!(
    WIDE_TABLE_CNODE_SLOTS.is_power_of_two()
        && MAX_TASK_ALLOCATIONS < u32::MAX as usize
        && MAX_TASK_EXTENTS < u16::MAX as usize
);
// Records per metadata page are reported in the census lines the private-memory
// gates read, so a record that grew would move those figures.
const _: () = assert!(
    core::mem::size_of::<Option<ExtentRecord>>() == 72
        && core::mem::size_of::<AllocationRecord>() == 32
);
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PrivateRecordVisits {
    reusable: usize,
    mark: usize,
    reset: usize,
    commit: usize,
    unwind: usize,
}

pub struct ObjectAllocator {
    slots: SlotPool,
    infrastructure: infrastructure::Infrastructure,
    adaptive_funding: Option<funding::Funding>,
    adaptive_reserve: Option<u64>,
    #[cfg(slime_private_fragmentation)]
    physically_withheld_ordinary: Option<u64>,
    operational_resources: boot_contracts::private_memory_policy::ledger::Resources,
    operational_lent: bool,
    metadata_ledger: segmented::Segmented<Option<infrastructure::MappingOwnership>>,
    metadata_next: usize,
    infrastructure_slot_next: usize,
    metadata_pending: Option<usize>,
    metadata_growing_ledger: bool,
    infrastructure_leaf_end: usize,
    infrastructure_path_depth: usize,
    /// Workload slot leaves admitted beyond the initial CNode namespace.
    expanded_leaves: usize,
    untypeds: [Option<UntypedRegion>; MAX_KERNEL_UNTYPEDS],
    untyped_len: usize,
    preserved: preserved::PreservedStore,
    /// Span-ownership records private regions hold pointers into.
    leaf_spans: leaf_spans::LeafSpanStore,
    devices: [Option<DeviceRegion>; MAX_DEVICE_UNTYPEDS],
    device_len: usize,
    arenas: [ArenaRecord; MAX_TASK_ARENAS],
    extents: record_tables::ExtentTable,
    allocations: record_tables::AllocationTable,
    allocation_search_start: usize,
    next_arena_serial: u32,
    slots_allocated: usize,
    objects_allocated: usize,
    bytes_allocated: usize,
    global_object_backing_bytes: u64,
    live_objects: usize,
    live_bytes: usize,
    slots_reused: usize,
    extents_reused: usize,
    last_paddr: usize,
    physical: ProvenanceTable,
    shared_backing: shared_backing::BuddyBacking,
    mapping_tables: mapping_tables::MappingTables,
    /// Reservation identities owning backing extents outside common capacity.
    reservations: guarantee_vault::ReservationTable,
    /// Each arena's failed elastic rollbacks, still owned and still retryable.
    ///
    /// Per arena, so one holder's failure never overwrites another's record;
    /// the arena's own revoke at retirement recovers whatever is still named.
    elastic_quarantine: [elastic::Quarantine; MAX_TASK_ARENAS],
    #[cfg(test)]
    private_visits: PrivateRecordVisits,
}

impl ObjectAllocator {
    pub const fn empty() -> Self {
        Self {
            slots: SlotPool::EMPTY,
            infrastructure: infrastructure::Infrastructure::new(),
            adaptive_funding: None,
            adaptive_reserve: None,
            #[cfg(slime_private_fragmentation)]
            physically_withheld_ordinary: None,
            operational_resources: boot_contracts::private_memory_policy::ledger::Resources::ZERO,
            operational_lent: false,
            metadata_ledger: segmented::Segmented::new(),
            metadata_next: infrastructure::METADATA_BASE,
            infrastructure_slot_next: 0,
            metadata_pending: None,
            metadata_growing_ledger: false,
            infrastructure_leaf_end: 0,
            infrastructure_path_depth: 0,
            expanded_leaves: 0,
            untypeds: [None; MAX_KERNEL_UNTYPEDS],
            untyped_len: 0,
            preserved: preserved::PreservedStore::new(),
            leaf_spans: leaf_spans::LeafSpanStore::new(),
            devices: [None; MAX_DEVICE_UNTYPEDS],
            device_len: 0,
            arenas: [ArenaRecord::empty(); MAX_TASK_ARENAS],
            extents: record_tables::ExtentTable::new(),
            allocations: record_tables::AllocationTable::new(),
            allocation_search_start: 0,
            next_arena_serial: 1,
            slots_allocated: 0,
            objects_allocated: 0,
            bytes_allocated: 0,
            global_object_backing_bytes: 0,
            live_objects: 0,
            live_bytes: 0,
            slots_reused: 0,
            extents_reused: 0,
            last_paddr: 0,
            physical: ProvenanceTable::new(),
            shared_backing: shared_backing::BuddyBacking::new(),
            mapping_tables: mapping_tables::MappingTables::new(),
            reservations: guarantee_vault::ReservationTable::new(),
            elastic_quarantine: [elastic::Quarantine::EMPTY; MAX_TASK_ARENAS],
            #[cfg(test)]
            private_visits: PrivateRecordVisits {
                reusable: 0,
                mark: 0,
                reset: 0,
                commit: 0,
                unwind: 0,
            },
        }
    }

    pub fn initialize(&mut self, bootinfo: &sel4::BootInfo) -> Result<(), AllocError> {
        let kernel_untypeds = bootinfo.kernel_untyped_range();
        let declared = kernel_untypeds.len();
        if declared > MAX_KERNEL_UNTYPEDS {
            return Err(AllocError::UntypedTableFull {
                limit: MAX_KERNEL_UNTYPEDS,
                declared,
            });
        }
        let empty = bootinfo.empty().range();
        let ordinary_start = empty
            .start
            .checked_add(infrastructure::Infrastructure::bootstrap_slots())
            .filter(|start| *start < empty.end)
            .ok_or(AllocError::SlotsExhausted { allocated: 0 })?;
        self.slots.initialize(ordinary_start..empty.end)?;
        let descriptors = bootinfo.untyped_list();
        let infrastructure_index = kernel_untypeds
            .clone()
            .filter(|index| {
                descriptors.get(*index).is_some_and(|region| {
                    !region.is_device()
                        && region.size_bits() < usize::BITS as usize
                        && (1usize << region.size_bits())
                            >= infrastructure::Infrastructure::bootstrap_bytes()
                })
            })
            .min_by_key(|index| descriptors[*index].size_bits())
            .ok_or(AllocError::NoKernelUntyped)?;
        let descriptor = &descriptors[infrastructure_index];
        self.infrastructure.initialize(
            UntypedRegion {
                cap: bootinfo.untyped().index(infrastructure_index).cap(),
                paddr: descriptor.paddr(),
                size_bits: descriptor.size_bits(),
                watermark: 0,
            },
            empty.start,
        )?;
        for index in kernel_untypeds {
            let Some(descriptor) = descriptors.get(index) else {
                continue;
            };
            if descriptor.is_device() {
                continue;
            }
            self.untypeds[self.untyped_len] = Some(UntypedRegion {
                cap: bootinfo.untyped().index(index).cap(),
                paddr: descriptor.paddr(),
                size_bits: descriptor.size_bits(),
                watermark: if index == infrastructure_index {
                    1usize << descriptor.size_bits()
                } else {
                    0
                },
            });
            self.untyped_len += 1;
        }
        if self.untyped_len == 0 {
            return Err(AllocError::NoKernelUntyped);
        }

        // seL4 resets an untyped's cursor when it has no descendants. Keep a
        // tracked minimum-size child alive so deleting ordinary objects cannot
        // invalidate the allocator's physical-address prediction. The child's
        // bytes remain available through preserved-leaf allocation.
        if self.untyped_len > self.free_slots() {
            return Err(AllocError::SlotsExhausted {
                allocated: self.slots_allocated,
            });
        }
        for index in 0..self.untyped_len {
            let region = self.untypeds[index].ok_or(AllocError::NoKernelUntyped)?;
            crate::diagnostic_println!(
                "SLIME_BACKING inventory parent={} paddr={} bytes={}",
                region.cap.bits(),
                region.paddr,
                region.capacity(),
            );
            if region.watermark == region.capacity() {
                crate::diagnostic_println!(
                    "SLIME_BACKING infrastructure parent={} anchor={} paddr={} bytes={}",
                    region.cap.bits(),
                    empty.start,
                    region.paddr,
                    region.capacity(),
                );
                crate::diagnostic_println!(
                    "SLIME_ROOT infrastructure parent={} paddr={} bytes={} reserved_slots={}",
                    region.cap.bits(),
                    region.paddr,
                    region.capacity(),
                    infrastructure::Infrastructure::bootstrap_slots(),
                );
                continue;
            }
            let anchor_bytes = if region.capacity() <= GRANULE_BYTES {
                region.capacity()
            } else {
                1 << global_backing::MINIMUM_BITS
            };
            self.preserve_global_prefix(index, anchor_bytes)?;
        }

        let device_untypeds = bootinfo.device_untyped_range();
        let device_declared = device_untypeds.len();
        for index in device_untypeds {
            let Some(descriptor) = descriptors.get(index) else {
                continue;
            };
            let Some(dst) = self.devices.get_mut(self.device_len) else {
                return Err(AllocError::DeviceTableFull {
                    limit: MAX_DEVICE_UNTYPEDS,
                    declared: device_declared,
                });
            };
            *dst = Some(DeviceRegion {
                cap: bootinfo.untyped().index(index).cap(),
                paddr: descriptor.paddr(),
                size_bits: descriptor.size_bits(),
                retyped: 0,
            });
            self.device_len += 1;
        }
        Ok(())
    }

    pub fn initialize_metadata(&mut self, bootinfo: &sel4::BootInfo) -> Result<(), AllocError> {
        unsafe extern "C" {
            static __executable_start: usize;
        }
        let image_start = core::ptr::addr_of!(__executable_start) as usize;
        let image_bytes = bootinfo
            .user_image_frames()
            .range()
            .len()
            .checked_mul(GRANULE_BYTES)
            .ok_or(AllocError::NoKernelUntyped)?;
        let boot_start = bootinfo as *const sel4::BootInfo as usize;
        let boot_bytes = GRANULE_BYTES
            .checked_add(bootinfo.inner().extraLen as usize)
            .ok_or(AllocError::NoKernelUntyped)?;
        for (start, bytes) in [
            (image_start, image_bytes),
            (boot_start, boot_bytes),
            (bootinfo.ipc_buffer() as usize, GRANULE_BYTES),
        ] {
            let end = start
                .checked_add(bytes)
                .ok_or(AllocError::NoKernelUntyped)?;
            if start < infrastructure::METADATA_END && infrastructure::METADATA_BASE < end {
                return Err(AllocError::NoKernelUntyped);
            }
        }
        if self.metadata_ledger.len() != 0 {
            return Err(AllocError::NoKernelUntyped);
        }
        let frame = self
            .infrastructure
            .map_page(infrastructure::METADATA_BASE)?;
        let page = core::ptr::NonNull::new(infrastructure::METADATA_BASE as *mut u8)
            .ok_or(AllocError::NoKernelUntyped)?;
        // SAFETY: the bootstrap mapper exclusively owns this reserved page;
        // it stays mapped for the allocator lifetime and is published once.
        unsafe { self.metadata_ledger.append(page, None) }
            .map_err(|()| AllocError::NoKernelUntyped)?;
        self.infrastructure.finish_mapping(|owned| {
            if owned.frame != frame {
                return Err(AllocError::NoKernelUntyped);
            }
            *self
                .metadata_ledger
                .get_mut(0)
                .ok_or(AllocError::NoKernelUntyped)? = Some(owned);
            Ok(())
        })?;
        // A full-width expanded path consumes four root bits followed by six
        // ten-bit nodes. Its leaf is independent of the BootInfo namespace.
        let expanded = 1usize << 60;
        for depth in [4, 14, 24, 34, 44, 54] {
            self.infrastructure
                .install_node(expanded >> (64 - depth), depth)?;
        }
        let owned = self
            .metadata_ledger
            .get_mut(0)
            .expect("bootstrap ledger")
            .as_mut()
            .expect("mapping ownership");
        let mut destination = expanded;
        self.infrastructure.drain(owned.frame, destination)?;
        owned.frame = destination;
        destination += 1;
        for table in owned.tables.iter_mut().flatten() {
            self.infrastructure.drain(*table, destination)?;
            *table = destination;
            destination += 1;
        }
        self.metadata_next = infrastructure::METADATA_BASE + GRANULE_BYTES;
        self.infrastructure_slot_next = destination;
        self.infrastructure_leaf_end = expanded + crate::root_cspace::LEAF_SLOTS;
        let second_page = self.map_metadata_page()?;
        // SAFETY: map_metadata_page transfers a fresh, exclusively owned page;
        // its frame and tables are already retained in the ownership ledger.
        unsafe { self.metadata_ledger.append(second_page, None) }
            .map_err(|()| AllocError::NoKernelUntyped)?;
        let remaining = self.slots.unadmitted_initial();
        while self.slots.metadata_free() < remaining.len().div_ceil(usize::BITS as usize) {
            let page = self.map_metadata_page()?;
            // SAFETY: this exclusively owned page is retained by the ledger.
            unsafe { self.slots.words.append(page, slots::SlotWord::EMPTY) }
                .map_err(|()| AllocError::NoKernelUntyped)?;
        }
        self.slots.admit(remaining)?;
        crate::diagnostic_println!(
            "SLIME_ROOT cspace expanded base={} infrastructure_caps={}",
            expanded,
            destination - expanded,
        );
        crate::diagnostic_println!(
            "SLIME_ROOT metadata bootstrap objects={} alignment={} remaining={}",
            self.infrastructure.object_bytes(),
            self.infrastructure.alignment_bytes(),
            self.infrastructure.remaining_bytes(),
        );
        Ok(())
    }

    fn replenish_infrastructure(&mut self, bytes: usize) -> Result<(), AllocError> {
        if !self.infrastructure.needs_source(bytes) {
            return Ok(());
        }
        let found = self.untypeds[..self.untyped_len]
            .iter()
            .enumerate()
            .filter_map(|(index, source)| {
                source
                    .filter(|source| source.watermark != 0 && source.remaining() >= bytes)
                    .map(|source| (index, source))
            })
            .min_by_key(|(_, source)| source.remaining());
        let Some((index, source)) = found else {
            // No ordinary tail can fund it, but returned capacity may. The
            // original refusal stands if no free extent is large enough.
            let refusal = AllocError::UntypedExhausted {
                size_bits: 12,
                remaining: self.untyped_bytes_remaining(),
            };
            return self
                .adopt_returned_extent(bytes)
                .map_err(|error| match error {
                    AllocError::AdaptiveFunding { .. } => error,
                    _ => refusal,
                });
        };
        self.check_root_funding(source.remaining())?;
        self.infrastructure.adopt_pinned_source(source)?;
        self.consume_root_funding(source.remaining())?;
        self.untypeds[index]
            .as_mut()
            .expect("adopted source")
            .watermark = source.capacity();
        crate::diagnostic_println!(
            "SLIME_BACKING infrastructure_tail parent={} paddr={} bytes={}",
            source.cap.bits(),
            source.paddr + source.watermark,
            source.remaining(),
        );
        Ok(())
    }

    fn ensure_infrastructure_slots(&mut self, needed: usize) -> Result<(), AllocError> {
        if self
            .infrastructure_slot_next
            .checked_add(needed)
            .is_some_and(|end| end <= self.infrastructure_leaf_end)
        {
            return Ok(());
        }
        let base = self.infrastructure_leaf_end;
        let end =
            base.checked_add(crate::root_cspace::LEAF_SLOTS)
                .ok_or(AllocError::SlotsExhausted {
                    allocated: self.infrastructure_slot_next,
                })?;
        if self.infrastructure_path_depth == 0 {
            self.infrastructure_path_depth = [4, 14, 24, 34, 44, 54]
                .into_iter()
                .find(|depth| base >> (64 - depth) != (base - 1) >> (64 - depth))
                .ok_or(AllocError::SlotsExhausted {
                    allocated: self.infrastructure_slot_next,
                })?;
        }
        while self.infrastructure_path_depth <= 54 {
            self.replenish_infrastructure(
                2 * (1usize << crate::root_cspace::leaf_blueprint().physical_size_bits()),
            )?;
            let depth = self.infrastructure_path_depth;
            self.infrastructure
                .install_node(base >> (64 - depth), depth)?;
            self.infrastructure_path_depth += 10;
        }
        self.infrastructure_slot_next = base;
        self.infrastructure_leaf_end = end;
        self.infrastructure_path_depth = 0;
        Ok(())
    }

    fn map_metadata_page(&mut self) -> Result<core::ptr::NonNull<u8>, AllocError> {
        // Host tests own their record pages directly: no kernel is present to
        // retype or map another one, so growth must refuse rather than invoke.
        if cfg!(test) {
            return Err(AllocError::NoKernelUntyped);
        }
        if self.metadata_pending.is_none()
            && self
                .metadata_ledger
                .iter()
                .filter(|record| record.is_none())
                .count()
                == 1
        {
            self.metadata_growing_ledger = true;
        }
        if self.metadata_growing_ledger {
            let page = self.map_metadata_page_inner()?;
            // SAFETY: this fresh mapped page has retained frame/table ownership
            // in the last free ledger record and is not used by another table.
            unsafe { self.metadata_ledger.append(page, None) }
                .map_err(|()| AllocError::NoKernelUntyped)?;
            self.metadata_growing_ledger = false;
        }
        self.map_metadata_page_inner()
    }

    fn map_metadata_page_inner(&mut self) -> Result<core::ptr::NonNull<u8>, AllocError> {
        let record = if let Some(record) = self.metadata_pending {
            record
        } else {
            self.metadata_ledger
                .iter()
                .position(Option::is_none)
                .ok_or(AllocError::NoKernelUntyped)?
        };
        let address = self.metadata_next;
        let next = address
            .checked_add(GRANULE_BYTES)
            .filter(|next| *next <= infrastructure::METADATA_END)
            .ok_or(AllocError::NoKernelUntyped)?;
        let needed = if self.metadata_pending.is_some() {
            let owned = self
                .metadata_ledger
                .get(record)
                .and_then(Option::as_ref)
                .ok_or(AllocError::NoKernelUntyped)?;
            usize::from(owned.frame < 1usize << 60)
                + owned
                    .tables
                    .iter()
                    .flatten()
                    .filter(|slot| **slot < 1usize << 60)
                    .count()
        } else {
            sel4::vspace_levels::NUM_LEVELS
        };
        self.ensure_infrastructure_slots(needed)?;
        if self.metadata_pending.is_none() {
            self.replenish_infrastructure((sel4::vspace_levels::NUM_LEVELS + 1) * GRANULE_BYTES)?;
            self.infrastructure.map_page(address)?;
            self.infrastructure.finish_mapping(|owned| {
                // The injection refuses exactly where a durable record could
                // not be written: the mapping transaction keeps its frame and
                // tables, and no other owner may name them until a retry.
                #[cfg(slime_metadata_lifecycle)]
                if INJECT_LEDGER_RETAIN.swap(false, core::sync::atomic::Ordering::Relaxed) {
                    return Err(AllocError::NoKernelUntyped);
                }
                *self
                    .metadata_ledger
                    .get_mut(record)
                    .ok_or(AllocError::NoKernelUntyped)? = Some(owned);
                Ok(())
            })?;
            self.metadata_pending = Some(record);
        }
        let owned = self
            .metadata_ledger
            .get_mut(record)
            .expect("reserved ownership record")
            .as_mut()
            .expect("mapping ownership");
        if owned.frame < 1usize << 60 {
            self.infrastructure
                .drain(owned.frame, self.infrastructure_slot_next)?;
            owned.frame = self.infrastructure_slot_next;
            self.infrastructure_slot_next += 1;
        }
        for table in owned.tables.iter_mut().flatten() {
            if *table < 1usize << 60 {
                self.infrastructure
                    .drain(*table, self.infrastructure_slot_next)?;
                *table = self.infrastructure_slot_next;
                self.infrastructure_slot_next += 1;
            }
        }
        self.metadata_next = next;
        self.metadata_pending = None;
        core::ptr::NonNull::new(address as *mut u8).ok_or(AllocError::NoKernelUntyped)
    }

    pub const fn slots_remaining(&self) -> usize {
        self.slots.remaining()
    }
    pub const fn slots_allocated(&self) -> usize {
        self.slots_allocated
    }
    pub const fn live_slots(&self) -> usize {
        self.slots.live
    }
    pub const fn slots_reused(&self) -> usize {
        self.slots_reused
    }
    pub const fn objects_allocated(&self) -> usize {
        self.objects_allocated
    }
    pub const fn live_objects(&self) -> usize {
        self.live_objects
    }
    pub const fn bytes_allocated(&self) -> usize {
        self.bytes_allocated
    }
    pub const fn live_bytes(&self) -> usize {
        self.live_bytes
    }
    pub const fn extents_reused(&self) -> usize {
        self.extents_reused
    }

    /// Root capabilities retained as lifetime anchors for reusable extents.
    ///
    /// Reservation-owned anchors are excluded here and reported by
    /// [`Self::reserved_extent_anchors`] instead, so each anchor appears in
    /// exactly one of the two counts.
    pub fn reusable_extent_anchors(&self) -> usize {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| extent.is_common_free())
            .count()
    }

    /// Bytes task arenas and reservations hold in extents.
    ///
    /// An extent adopted for infrastructure is counted by
    /// [`Self::infrastructure_owned_bytes`] alone.
    pub fn active_extent_bytes(&self) -> usize {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| extent.active && extent.kind != ExtentKind::Infrastructure)
            .map(|extent| 1usize << extent.size_bits)
            .sum()
    }

    pub fn reusable_extent_bytes(&self) -> usize {
        let bytes = self.extents.free_bytes();
        #[cfg(test)]
        assert_eq!(
            bytes,
            self.extents.recount_free_bytes(),
            "recount: reusable extent bytes"
        );
        bytes
    }

    /// [`Self::reusable_extent_bytes`], restricted to private-backing extents.
    ///
    /// The unrestricted total is satisfied by any inactive extent, including
    /// the one every task carries for its static construction; a private
    /// holder whose data or table extents never returned to the free list
    /// would still read as nonzero reclamation. This is the kind-scoped
    /// evidence that a private extent specifically was reclaimed rather than
    /// leaked.
    pub fn reusable_private_extent_bytes(&self) -> usize {
        self.extents
            .iter()
            .flatten()
            .filter(|extent| {
                extent.is_common_free()
                    && matches!(
                        extent.kind,
                        ExtentKind::PrivateData | ExtentKind::PrivateTables
                    )
            })
            .map(|extent| 1usize << extent.size_bits)
            .sum()
    }
    pub const fn untyped_count(&self) -> usize {
        self.untyped_len
    }
    pub const fn device_untyped_count(&self) -> usize {
        self.device_len
    }
    /// Physical base retained for a live root CSlot allocated from ordinary RAM.
    /// This root-only mechanism seam is public because the binary links the
    /// allocator through the library crate; no component ABI exposes it.
    ///
    /// `None` for a slot that never held a DMA-capable frame, and for one whose
    /// frame has been released: a caller reaching for an address the root no
    /// longer owns must be refused, not answered from a stale record.
    pub fn physical_address_of(&self, slot: usize) -> Option<usize> {
        self.physical.get(slot)
    }

    /// Live entries in the bounded physical-provenance table.
    pub const fn physical_provenance_len(&self) -> usize {
        self.physical.len
    }

    pub fn untyped_bytes_remaining(&self) -> usize {
        self.regions()
            .iter()
            .flatten()
            .map(UntypedRegion::remaining)
            .sum()
    }

    /// Every admitted ordinary untyped range, in BootInfo order.
    ///
    /// The aggregate remaining-byte count is not evidence of a platform's
    /// physical window: a stale kernel description yields fewer or smaller
    /// ranges while the launcher's `-m` is unchanged. Reporting each range's
    /// physical base is what makes the kernel-visible window observable, and
    /// what lets a probe target an address the previous platform did not
    /// contain.
    pub fn ordinary_ranges(&self) -> impl Iterator<Item = OrdinaryRange> + '_ {
        self.untypeds
            .iter()
            .take(self.untyped_len)
            .flatten()
            .map(|region| OrdinaryRange {
                paddr: region.paddr,
                bytes: region.capacity(),
                used: region.watermark,
            })
    }

    /// Highest physical address any admitted ordinary range covers.
    ///
    /// The upper bound of kernel-visible RAM, which a platform raise must move
    /// and a launcher-only `-m` change cannot.
    pub fn ordinary_physical_end(&self) -> usize {
        self.ordinary_ranges()
            .map(|range| range.paddr.saturating_add(range.bytes))
            .max()
            .unwrap_or(0)
    }

    /// Whether admitted resources can place every planned extent in
    /// provisioning order under seL4's object-size alignment rule.
    ///
    /// Planning storage and root CSpace both grow from admitted ordinary
    /// resources, exactly as live provisioning grows them, so a shortfall the
    /// allocator can still fund is not the platform's limit. Exhausting that
    /// funding is, and the refusal then names the resource that ran out.
    pub fn task_backing_extents_fit(
        &mut self,
        plan: TaskBackingPlan,
        static_backing: TaskStaticBacking,
        holders: usize,
    ) -> Result<(), LayoutLimit> {
        if plan_task_backing(plan.private_pages) != Some(plan) {
            return Err(LayoutLimit::Placement);
        }
        if !static_backing.reserved_bytes.is_power_of_two() {
            return (holders == 0).then_some(()).ok_or(LayoutLimit::Placement);
        }
        loop {
            // A shortfall is the deficit beyond the headroom the plan already
            // consumed, so funding must raise today's headroom rather than
            // restate it; every round therefore ends or grows a resource.
            match self.simulate_task_backing(plan, static_backing, holders) {
                Ok(()) => return Ok(()),
                Err(global_backing::PlanShortfall::Records(deficit)) => {
                    let target = (self.preserved.capacity() - self.preserved.len())
                        .checked_add(deficit)
                        .ok_or(LayoutLimit::MetadataRecords)?;
                    self.ensure_preserved_records(target)
                        .map_err(|_| LayoutLimit::MetadataRecords)?;
                }
                Err(global_backing::PlanShortfall::Slots(deficit)) => {
                    let target = self
                        .free_slots()
                        .checked_add(deficit)
                        .ok_or(LayoutLimit::RootSlots)?;
                    self.ensure_root_slots(target)
                        .map_err(|_| LayoutLimit::RootSlots)?;
                }
                Err(global_backing::PlanShortfall::Placement) => {
                    return Err(LayoutLimit::Placement);
                }
            }
        }
    }

    /// Replay provisioning against planning mirrors of the live registries,
    /// leaving live ownership untouched whether the plan fits or refuses.
    fn simulate_task_backing(
        &mut self,
        plan: TaskBackingPlan,
        static_backing: TaskStaticBacking,
        holders: usize,
    ) -> Result<(), global_backing::PlanShortfall> {
        let Some(non_parent) = plan
            .allocation_descriptors
            .checked_add(static_backing.allocation_descriptors)
        else {
            return Err(global_backing::PlanShortfall::Placement);
        };
        let mut slots = self.free_slots();
        let mut slot_pool = self.slots.planner();
        let mut regions = self.untypeds;
        let untyped_len = self.untyped_len;
        let mut preserved = self.preserved.planner();
        let layout = PrivateBackingLayout::for_pages(plan.private_pages);
        for _ in 0..holders {
            global_backing::plan_extent_with_slots(
                &mut regions[..untyped_len],
                &mut preserved,
                &mut slots,
                static_backing.reserved_bytes.trailing_zeros() as usize,
                Some(&mut slot_pool),
            )?;
            let mut index = 0;
            while let Some(extent) = layout.extent(index) {
                global_backing::plan_extent_with_slots(
                    &mut regions[..untyped_len],
                    &mut preserved,
                    &mut slots,
                    extent.size_bits,
                    Some(&mut slot_pool),
                )?;
                index += 1;
            }
            // Runtime reserves payload descriptors and static object slots
            // after the holder's parent extents, before the next holder.
            let Some(remaining) = slots.checked_sub(non_parent) else {
                return Err(global_backing::PlanShortfall::Slots(non_parent - slots));
            };
            for _ in 0..non_parent {
                if slot_pool.allocate(0).is_err() {
                    return Err(global_backing::PlanShortfall::Slots(1));
                }
            }
            slots = remaining;
        }
        Ok(())
    }

    fn ensure_root_slots(&mut self, free: usize) -> Result<(), AllocError> {
        while self.free_slots() < free {
            if self.metadata_ledger.len() == 0 {
                return Err(AllocError::SlotsExhausted {
                    allocated: self.slots_allocated,
                });
            }
            let words = crate::root_cspace::LEAF_SLOTS.div_ceil(usize::BITS as usize);
            while self.slots.metadata_free() < words {
                if self.slots.words.needs_directory_page() {
                    let page = self.map_metadata_page()?;
                    // SAFETY: the ledger retains this fresh page exclusively
                    // as the slot table's next directory page.
                    unsafe { self.slots.words.add_directory_page(page) }
                        .map_err(|()| AllocError::NoKernelUntyped)?;
                }
                let page = self.map_metadata_page()?;
                // SAFETY: the infrastructure ledger retains this fresh mapping
                // exclusively for slot occupancy and planning scratch.
                unsafe { self.slots.words.append(page, slots::SlotWord::EMPTY) }
                    .map_err(|()| AllocError::NoKernelUntyped)?;
            }
            // Keep infrastructure and workload leaves disjoint. Complete the
            // next leaf before transferring its empty slots to the live pool.
            self.ensure_infrastructure_slots(crate::root_cspace::LEAF_SLOTS)?;
            let base = self.infrastructure_slot_next;
            let end = base
                .checked_add(crate::root_cspace::LEAF_SLOTS)
                .ok_or(AllocError::NoKernelUntyped)?;
            self.slots.admit(base..end)?;
            self.infrastructure_slot_next = end;
            self.expanded_leaves += 1;
            #[cfg(slime_cspace_expanded)]
            crate::diagnostic_println!(
                "SLIME_ROOT cspace leaf base={} slots={} beyond_initial={}",
                base,
                crate::root_cspace::LEAF_SLOTS,
                u8::from(base >= KERNEL_ROOT_CNODE_SLOTS),
            );
        }
        Ok(())
    }

    fn ensure_contiguous_root_slots(&mut self, count: usize) -> Result<(), AllocError> {
        if count == 0 || count > crate::root_cspace::LEAF_SLOTS {
            return Err(AllocError::SlotsExhausted {
                allocated: self.slots_allocated,
            });
        }
        self.ensure_root_slots(count)?;
        if self.slots.first_contiguous(count, None).is_none() {
            let required = self
                .free_slots()
                .checked_add(crate::root_cspace::LEAF_SLOTS)
                .ok_or(AllocError::SlotsExhausted {
                    allocated: self.slots_allocated,
                })?;
            self.ensure_root_slots(required)?;
        }
        Ok(())
    }

    /// Grow the slot pool toward `required` before an admission decision.
    ///
    /// Root CSpace grows from admitted ordinary memory, so a plan larger than
    /// today's free slots is not refused by that fact alone. A refusal here is
    /// left for the caller to report against what growth actually achieved.
    pub fn fund_root_slots(&mut self, required: usize) {
        let _ = self.ensure_root_slots(required);
    }

    fn take_slot(&mut self) -> Result<usize, AllocError> {
        self.ensure_root_slots(1)?;
        let (slot, reused) = self.slots.allocate(self.slots_allocated)?;
        self.slots_reused += usize::from(reused);
        self.slots_allocated += 1;
        Ok(slot)
    }

    fn allocate_from_global(
        &mut self,
        blueprint: sel4::ObjectBlueprint,
        slot_index: usize,
    ) -> Result<(), AllocError> {
        if self.allocate_preserved(blueprint, slot_index)? {
            return Ok(());
        }
        let size_bits = blueprint.physical_size_bits();
        let (region_index, start, watermark) = self
            .untypeds
            .iter()
            .take(self.untyped_len)
            .enumerate()
            .find_map(|(index, region)| {
                let region = region.as_ref()?;
                plan_allocation(region.watermark, region.capacity(), size_bits)
                    .map(|(start, end)| (index, start, end))
            })
            .ok_or(AllocError::UntypedExhausted {
                size_bits,
                remaining: self.untyped_bytes_remaining(),
            })?;
        let region = self.untypeds[region_index].ok_or(AllocError::UntypedExhausted {
            size_bits,
            remaining: 0,
        })?;
        let paddr = region.paddr.saturating_add(start);
        // Recorded *before* the retype, so an exhausted table refuses the
        // allocation while it is still free to refuse: the slot is not yet
        // occupied, so releasing it back to the pool leaves nothing behind. The
        // retype's own failure path undoes the record below. Recording
        // afterwards would mean either a live capability with no recoverable
        // physical base, or a slot released while still holding one — the
        // `DeleteFirst` hazard [`Self::release_slot`] documents.
        self.preserve_global_prefix(region_index, start)?;
        if self.untypeds[region_index].is_none_or(|current| current.watermark != start) {
            // Funding prefix records can adopt this tail for infrastructure.
            return self.allocate_from_global(blueprint, slot_index);
        }
        self.check_common_funding(1usize << size_bits)?;
        let recorded = records_provenance(blueprint);
        if recorded {
            self.physical.insert(slot_index, paddr)?;
        }
        if let Err(error) = crate::root_cspace::retype(region.cap, &blueprint, slot_index, 1) {
            if recorded {
                self.physical.remove(slot_index);
            }
            return Err(AllocError::Retype { size_bits, error });
        }
        if let Some(region) = self.untypeds[region_index].as_mut() {
            region.watermark = watermark;
        }
        self.consume_payload_funding(1usize << size_bits)?;
        self.last_paddr = paddr;
        self.objects_allocated += 1;
        self.live_objects += 1;
        self.bytes_allocated += 1usize << size_bits;
        self.live_bytes += 1usize << size_bits;
        crate::diagnostic_println!(
            "SLIME_BACKING consume source=ordinary parent={} slot={} paddr={} bytes={} count=1",
            region.cap.bits(),
            slot_index,
            paddr,
            1usize << size_bits,
        );
        crate::diagnostic_println!(
            "SLIME_ALLOC global region={} parent={} slot={} prior={} start={} end={} bytes={} gap={}",
            region_index,
            region.cap.bits(),
            slot_index,
            region.watermark,
            start,
            watermark,
            1usize << size_bits,
            start - region.watermark,
        );
        Ok(())
    }

    pub fn allocate(
        &mut self,
        blueprint: sel4::ObjectBlueprint,
    ) -> Result<crate::root_cspace::RootSlot<sel4::cap_type::Unspecified>, AllocError> {
        let global_bytes = self
            .global_object_backing_bytes
            .checked_add(1u64 << blueprint.physical_size_bits())
            .ok_or(AllocError::AdaptiveFunding {
                resource: "arithmetic",
                required: 0,
                available: 0,
            })?;
        let slot = self.take_slot()?;
        if let Err(error) = self.allocate_from_global(blueprint, slot) {
            self.slots.release(slot);
            return Err(error);
        }
        self.global_object_backing_bytes = global_bytes;
        Ok(crate::root_cspace::RootSlot::from_address(slot))
    }

    pub fn allocate_fixed<T: sel4::CapTypeForObjectOfFixedSize>(
        &mut self,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        Ok(self.allocate(T::object_blueprint())?.cast())
    }

    /// Retype one base page from the highest admitted ordinary region.
    ///
    /// This root-only qualification seam deliberately bypasses the global
    /// first-fit order: a platform-capacity probe must touch RAM the previous
    /// physical window could not contain, not merely observe that a high range
    /// exists while allocating its test frame from the first range.
    pub fn allocate_last_ordinary_granule(
        &mut self,
    ) -> Result<crate::root_cspace::RootSlot<sel4::cap_type::Granule>, AllocError> {
        self.ensure_root_slots(1)?;
        let blueprint =
            <sel4::cap_type::Granule as sel4::CapTypeForObjectOfFixedSize>::object_blueprint();
        let size_bits = blueprint.physical_size_bits();
        let global_bytes = self
            .global_object_backing_bytes
            .checked_add(1u64 << size_bits)
            .ok_or(AllocError::AdaptiveFunding {
                resource: "arithmetic",
                required: 0,
                available: 0,
            })?;
        if let Some(index) = (0..self.preserved.len())
            .filter_map(|index| {
                self.preserved
                    .get(index)
                    .filter(|region| region.watermark == 0 && region.size_bits == size_bits)
                    .map(|region| (index, region.paddr))
            })
            .max_by_key(|(_, paddr)| *paddr)
            .filter(|(_, paddr)| {
                self.untypeds[..self.untyped_len]
                    .iter()
                    .flatten()
                    .filter_map(|region| {
                        plan_allocation(region.watermark, region.capacity(), size_bits)
                            .and_then(|(start, _)| region.paddr.checked_add(start))
                    })
                    .all(|candidate| candidate < *paddr)
            })
            .map(|(index, _)| index)
        {
            let slot = self.take_slot()?;
            if let Err(error) = self.allocate_preserved_leaf(blueprint, slot, index) {
                self.slots.release(slot);
                return Err(error);
            }
            self.global_object_backing_bytes = global_bytes;
            return Ok(crate::root_cspace::RootSlot::from_address(slot));
        }
        let (region_index, start, watermark) = self
            .untypeds
            .iter()
            .take(self.untyped_len)
            .enumerate()
            .filter_map(|(index, region)| {
                let region = region.as_ref()?;
                plan_allocation(region.watermark, region.capacity(), size_bits)
                    .map(|(start, end)| (index, region.paddr, start, end))
            })
            .max_by_key(|(_, paddr, _, _)| *paddr)
            .map(|(index, _, start, end)| (index, start, end))
            .ok_or(AllocError::UntypedExhausted {
                size_bits,
                remaining: self.untyped_bytes_remaining(),
            })?;
        let region = self.untypeds[region_index].ok_or(AllocError::UntypedExhausted {
            size_bits,
            remaining: 0,
        })?;
        let slot = self.take_slot()?;
        if let Err(error) = self.preserve_global_prefix(region_index, start) {
            self.slots.release(slot);
            return Err(error);
        }
        if let Err(error) = self.check_common_funding(1usize << size_bits) {
            self.slots.release(slot);
            return Err(error);
        }
        let paddr = region.paddr.saturating_add(start);
        if let Err(error) = self.physical.insert(slot, paddr) {
            self.slots.release(slot);
            return Err(error);
        }
        if let Err(error) = crate::root_cspace::retype(region.cap, &blueprint, slot, 1) {
            self.physical.remove(slot);
            self.slots.release(slot);
            return Err(AllocError::Retype { size_bits, error });
        }
        if let Some(region) = self.untypeds[region_index].as_mut() {
            region.watermark = watermark;
        }
        self.consume_payload_funding(1usize << size_bits)?;
        self.last_paddr = paddr;
        self.objects_allocated += 1;
        self.live_objects += 1;
        self.bytes_allocated += 1usize << size_bits;
        self.live_bytes += 1usize << size_bits;
        crate::diagnostic_println!(
            "SLIME_BACKING consume source=ordinary parent={} slot={} paddr={} bytes={} count=1",
            region.cap.bits(),
            slot,
            paddr,
            1usize << size_bits,
        );
        self.global_object_backing_bytes = global_bytes;
        Ok(crate::root_cspace::RootSlot::from_address(slot))
    }

    /// Retype `count` adjacent base pages from one ordinary untyped in one
    /// kernel operation. This is the provenance required by legacy virtqueues,
    /// whose PFN names one physically contiguous queue area.
    pub fn allocate_contiguous_granules(
        &mut self,
        count: usize,
    ) -> Result<(usize, usize), AllocError> {
        if count == 0 || count > MAX_CONTIGUOUS_GRANULES {
            return Err(AllocError::SlotsExhausted {
                allocated: self.slots_allocated,
            });
        }
        self.ensure_contiguous_root_slots(count)?;
        let blueprint =
            <sel4::cap_type::Granule as sel4::CapTypeForObjectOfFixedSize>::object_blueprint();
        let size_bits = blueprint.physical_size_bits();
        let page_bytes = 1usize << size_bits;
        let total = page_bytes
            .checked_mul(count)
            .ok_or(AllocError::UntypedExhausted {
                size_bits,
                remaining: self.untyped_bytes_remaining(),
            })?;
        let global_bytes = self
            .global_object_backing_bytes
            .checked_add(total as u64)
            .ok_or(AllocError::AdaptiveFunding {
                resource: "arithmetic",
                required: 0,
                available: 0,
            })?;
        let (region_index, start, watermark) = self
            .untypeds
            .iter()
            .take(self.untyped_len)
            .enumerate()
            .find_map(|(index, region)| {
                let region = region.as_ref()?;
                let start = region.watermark.checked_next_multiple_of(page_bytes)?;
                let end = start.checked_add(total)?;
                (end <= region.capacity()).then_some((index, start, end))
            })
            .ok_or(AllocError::UntypedExhausted {
                size_bits,
                remaining: self.untyped_bytes_remaining(),
            })?;
        let region = self.untypeds[region_index].ok_or(AllocError::UntypedExhausted {
            size_bits,
            remaining: 0,
        })?;
        let (first, reused) = self
            .slots
            .allocate_contiguous(count, self.slots_allocated)?;
        if let Err(error) = self.preserve_global_prefix(region_index, start) {
            for slot in first..first + count {
                self.slots.release(slot);
            }
            return Err(error);
        }
        if let Err(error) = self.check_common_funding(total) {
            for slot in first..first + count {
                self.slots.release(slot);
            }
            return Err(error);
        }
        let paddr = region.paddr.saturating_add(start);
        for index in 0..count {
            if let Err(error) = self
                .physical
                .insert(first + index, paddr + index * page_bytes)
            {
                for done in 0..index {
                    self.physical.remove(first + done);
                }
                for slot in first..first + count {
                    self.slots.release(slot);
                }
                return Err(error);
            }
        }
        if let Err(error) = crate::root_cspace::retype(region.cap, &blueprint, first, count) {
            for slot in first..first + count {
                self.physical.remove(slot);
                self.slots.release(slot);
            }
            return Err(AllocError::Retype { size_bits, error });
        }
        self.untypeds[region_index].as_mut().unwrap().watermark = watermark;
        self.consume_payload_funding(total)?;
        self.slots_allocated += count;
        self.slots_reused += reused;
        self.objects_allocated += count;
        self.live_objects += count;
        self.bytes_allocated += total;
        self.live_bytes += total;
        self.last_paddr = paddr + (count - 1) * page_bytes;
        crate::diagnostic_println!(
            "SLIME_BACKING consume source=ordinary parent={} slot={} paddr={} bytes={} count={}",
            region.cap.bits(),
            first,
            paddr,
            total,
            count,
        );
        self.global_object_backing_bytes = global_bytes;
        Ok((first, paddr))
    }

    pub fn allocate_variable<T: sel4::CapTypeForObjectOfVariableSize>(
        &mut self,
        size_bits: usize,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        Ok(self.allocate(T::object_blueprint(size_bits))?.cast())
    }

    pub fn reserve_slot<T: sel4::CapType>(
        &mut self,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        Ok(crate::root_cspace::RootSlot::from_address(
            self.take_slot()?,
        ))
    }

    /// Begin one task lifetime with an independently reclaimable static extent.
    /// Private quota backing is provisioned separately before construction.
    pub fn begin_task_arena(&mut self, size_bits: usize) -> Result<TaskArenaId, AllocError> {
        // Preserve the small-image construction reserve independently of the
        // aggregate descriptor envelope used for large images.
        self.ensure_allocation_descriptors(
            MAX_PLANNED_STATIC_ALLOCATIONS
                + boot_contracts::component_image::wire::DEFAULT_IMAGE_PAGES
                - 2,
        )?;
        let index = self.arenas.iter().position(|arena| !arena.active).ok_or(
            AllocError::ArenaTableFull {
                limit: MAX_TASK_ARENAS,
            },
        )?;
        let serial = self.next_arena_serial;
        self.next_arena_serial = self.next_arena_serial.wrapping_add(1).max(1);
        self.extents.reset_arena(index);
        self.arenas[index] = ArenaRecord {
            serial,
            active: true,
            ..ArenaRecord::empty()
        };
        let id = self.arenas[index].id(index);
        if let Err(error) = self.provision_extent(id, size_bits, ExtentKind::Static) {
            self.arenas[index] = ArenaRecord::empty();
            self.extents.reset_arena(index);
            return Err(error);
        }
        Ok(id)
    }

    fn arena(&self, id: TaskArenaId) -> Result<&ArenaRecord, AllocError> {
        self.arenas
            .get(id.index())
            .filter(|arena| arena.serial == id.serial && arena.active)
            .ok_or(AllocError::UnknownArena(id))
    }

    fn private_arena(&self, id: TaskArenaId) -> Result<&ArenaRecord, AllocError> {
        let arena = self.arena(id)?;
        if arena.releasing {
            Err(AllocError::UnknownArena(id))
        } else {
            Ok(arena)
        }
    }

    pub fn task_static_backing(&self, id: TaskArenaId) -> Option<TaskStaticBacking> {
        self.arena(id).ok()?;
        task_static_backing_from_records(id, self.allocations.iter(), self.extents.iter())
    }

    fn arena_mut(&mut self, id: TaskArenaId) -> Result<&mut ArenaRecord, AllocError> {
        self.arenas
            .get_mut(id.index())
            .filter(|arena| arena.serial == id.serial && arena.active)
            .ok_or(AllocError::UnknownArena(id))
    }

    fn private_record_error() -> AllocError {
        AllocError::ArenaSlotTableFull {
            limit: MAX_TASK_ALLOCATIONS,
        }
    }

    fn push_reusable(&mut self, id: TaskArenaId, position: usize) -> Result<(), AllocError> {
        let kind = self
            .allocations
            .get(position)
            .filter(|record| {
                record.belongs_to(id)
                    && record.allocation.is_private()
                    && record.allocation.is_reusable()
                    && !record.allocation.is_in_flight()
                    && record.next_state == PRIVATE_STATE_NONE
            })
            .ok_or_else(Self::private_record_error)?
            .allocation
            .private_kind();
        let head = self.private_arena(id)?.reusable_heads[kind as usize];
        self.allocations
            .update(position, |record| record.next_state = head);
        self.arena_mut(id)?.reusable_heads[kind as usize] = position as u32;
        Ok(())
    }

    fn pop_reusable(
        &mut self,
        id: TaskArenaId,
        kind: PrivateObjectKind,
        size_bits: Option<usize>,
    ) -> Result<Option<usize>, AllocError> {
        self.pop_reusable_from(id, kind, size_bits, None)
    }

    fn pop_reusable_from(
        &mut self,
        id: TaskArenaId,
        kind: PrivateObjectKind,
        size_bits: Option<usize>,
        source: impl Into<Option<ExtentSource>>,
    ) -> Result<Option<usize>, AllocError> {
        let source = source.into();
        let mut previous = PRIVATE_STATE_NONE;
        let mut current = self.private_arena(id)?.reusable_heads[kind as usize];
        let limit = self.private_arena(id)?.slot_len;
        for _ in 0..limit {
            if current == PRIVATE_STATE_NONE {
                return Ok(None);
            }
            let position = current as usize;
            #[cfg(test)]
            {
                self.private_visits.reusable += 1;
            }
            let record = self
                .allocations
                .get(position)
                .filter(|record| {
                    record.belongs_to(id)
                        && record.allocation.is_private()
                        && record.allocation.is_reusable()
                        && !record.allocation.is_in_flight()
                        && record.allocation.private_kind() == kind
                })
                .ok_or_else(Self::private_record_error)?;
            let next = record.next_state;
            let extent = record.extent;
            let matches_source = source.is_none_or(|source| {
                extent == PRIVATE_EXTENT_NONE || self.extent_matches_source(extent as usize, source)
            });
            if matches_source
                && size_bits.is_none_or(|expected| record.allocation.size_bits() == expected)
            {
                if previous == PRIVATE_STATE_NONE {
                    self.arena_mut(id)?.reusable_heads[kind as usize] = next;
                } else {
                    self.allocations
                        .update(previous as usize, |record| record.next_state = next);
                }
                self.allocations
                    .update(position, |record| record.next_state = PRIVATE_STATE_NONE);
                return Ok(Some(position));
            }
            previous = current;
            current = next;
        }
        Err(Self::private_record_error())
    }

    /// Where one committed private record of this arena lives.
    fn private_record_position(
        &self,
        id: TaskArenaId,
        allocation: &PrivateAllocation,
    ) -> Result<usize, AllocError> {
        self.private_arena(id)?;
        if allocation.arena != id {
            return Err(Self::private_record_error());
        }
        let position = allocation.position as usize;
        self.allocations
            .get(position)
            .filter(|record| {
                record.belongs_to(id)
                    && record.allocation.is_private()
                    && !record.allocation.is_reusable()
                    && !record.allocation.is_in_flight()
                    && record.allocation.private_kind() != PrivateObjectKind::Empty
                    && record.allocation.slot() == allocation.cap.bits() as usize
                    && record.next_state == PRIVATE_STATE_NONE
            })
            .map(|_| position)
            .ok_or_else(Self::private_record_error)
    }

    /// Obtain an extent record backed by a parent untyped of `size_bits`,
    /// without assigning an owner.
    ///
    /// Reuse selects only common free capacity, so a record a reservation owns
    /// is never re-served to a task arena or an elastic transaction.
    fn acquire_extent_record(&mut self, size_bits: usize) -> Result<usize, AllocError> {
        self.check_common_funding(1usize << size_bits)?;
        if let Some(index) = self.reusable_extent(size_bits) {
            self.consume_payload_funding(1usize << size_bits)?;
            self.extents_reused += 1;
            return Ok(index);
        }
        self.ensure_extent_descriptors(1)?;
        let vacancy = self.extents.first_vacancy();
        #[cfg(test)]
        assert_eq!(
            vacancy,
            self.extents.walk_vacancy(),
            "recount: lowest vacant extent slot"
        );
        let index = vacancy.ok_or(AllocError::ArenaTableFull {
            limit: MAX_TASK_EXTENTS,
        })?;
        let parent_slot = self.take_slot()?;
        let blueprint = sel4::ObjectBlueprint::Untyped { size_bits };
        if let Err(error) = self.allocate_from_global(blueprint, parent_slot) {
            self.slots.release(parent_slot);
            if matches!(error, AllocError::AdaptiveFunding { .. }) {
                return Err(error);
            }
            // Ordinary tails cannot place it, but returned capacity may: a
            // larger free extent is split rather than left unreachable to a
            // smaller request. The original refusal stands if none exists.
            // Host tests have no kernel to split with, and exercise the split
            // through `extent_buddy`'s injected operations instead.
            #[cfg(not(test))]
            return self.acquire_split_extent(size_bits).map_err(|split| {
                crate::diagnostic_println!(
                    "SLIME_MEM extent split refused size_bits={size_bits} error={split:?}"
                );
                match split {
                    AllocError::AdaptiveFunding { .. } => split,
                    _ => error,
                }
            });
            #[cfg(test)]
            return Err(error);
        }
        let parent =
            crate::root_cspace::RootSlot::<sel4::cap_type::Untyped>::from_address(parent_slot)
                .cap();
        let mut record = ExtentRecord::new(parent, size_bits);
        record.paddr = self.last_paddr;
        self.extents.set(index, Some(record));
        Ok(index)
    }

    fn provision_extent(
        &mut self,
        id: TaskArenaId,
        size_bits: usize,
        kind: ExtentKind,
    ) -> Result<usize, AllocError> {
        self.arena(id)?;
        let index = self.acquire_extent_record(size_bits)?;
        self.extents
            .update(index, |extent| extent.assign(id.index(), id.serial, kind));
        Ok(index)
    }

    /// Settle one extent record whose revoke has completed.
    ///
    /// The single return point for both release paths. A record a reservation
    /// owns keeps its `origin`, so settling returns it to that reservation;
    /// a record from common capacity becomes a reusable anchor. Nothing here
    /// is reachable until the revoke succeeded: a failed revoke leaves the
    /// record active and owned, which is what keeps a quarantine unavailable
    /// rather than advertised as free.
    fn settle_returned_extent(&mut self, index: usize) {
        self.extents.update_present(index, |record| {
            record.active = false;
            record.revoked = false;
            record.owner = u16::MAX;
            record.serial = 0;
            record.watermark = 0;
            record.objects = 0;
            record.bytes = 0;
        });
    }

    fn allocation_position(&self) -> Result<usize, AllocError> {
        (self.allocation_search_start..self.allocations.len())
            .chain(0..self.allocation_search_start)
            .find(|index| self.allocations[*index].owner == u16::MAX)
            .ok_or(AllocError::ArenaSlotTableFull {
                limit: MAX_TASK_ALLOCATIONS,
            })
    }

    fn push_allocation(
        &mut self,
        id: TaskArenaId,
        extent: Option<usize>,
        allocation: ArenaAllocation,
    ) -> Result<usize, AllocError> {
        let position = self.allocation_position()?;
        self.allocations.set(
            position,
            AllocationRecord {
                owner: id.index() as u16,
                extent: extent.map_or(PRIVATE_EXTENT_NONE, |index| index as u32),
                serial: id.serial,
                allocation,
                next_state: PRIVATE_STATE_NONE,
            },
        );
        self.arena_mut(id)?.slot_len += 1;
        self.allocation_search_start = (position + 1) % self.allocations.len();
        Ok(position)
    }

    /// Select the extent one object is retyped from.
    ///
    /// A fixed arena's private extents are all one size, so first fit is the
    /// selection it has always made. An elastic arena holds extents sized to
    /// the requests that acquired them, and there first fit would let a base
    /// page consume the aligned 2 MiB extent a large frame in the same
    /// transaction was planned to occupy, failing a growth whose resources all
    /// exist. Best fit by extent size keeps every planned mapping payable.
    /// Whether this extent is backing the named source may draw from.
    fn extent_matches_source(&self, index: usize, source: ExtentSource) -> bool {
        self.extents
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|extent| match source {
                ExtentSource::Common => !extent.is_borrowed(),
                ExtentSource::Guaranteed(id) => {
                    extent.is_borrowed() && extent.owned_by_reservation(id.index())
                }
            })
    }

    fn extent_for_allocation(
        &self,
        id: TaskArenaId,
        kind: ExtentKind,
        size_bits: usize,
        source: ExtentSource,
    ) -> Result<(usize, usize), AllocError> {
        // Static and mapping-table extents are chosen while a task is built
        // or admitted, not per page, and keep the walk below.
        if record_tables::room_rank(kind).is_none()
            || size_bits < GRANULE_BYTES.trailing_zeros() as usize
            || self.arena(id).is_err()
        {
            return self.walk_extent_for_allocation(id, kind, size_bits, source);
        }
        let selected = self.extents.room_select(id, kind, size_bits, source);
        #[cfg(test)]
        {
            if matches!(selected, Err(AllocError::ArenaTableFull { .. })) {
                assert!(
                    self.extents.out_of_step() || !self.extents.room_chain_sound(id.index()),
                    "recount: a sound room chain refused a request"
                );
            } else {
                let walked = self.uncounted(|allocator| {
                    allocator.walk_extent_for_allocation(id, kind, size_bits, source)
                });
                assert_eq!(
                    selected, walked,
                    "recount: the room chain disagrees with the walk"
                );
            }
        }
        selected
    }

    /// Every record of the table, in index order: the selection the room
    /// chain reproduces, and the one kinds without a chain still make.
    fn walk_extent_for_allocation(
        &self,
        id: TaskArenaId,
        kind: ExtentKind,
        size_bits: usize,
        source: ExtentSource,
    ) -> Result<(usize, usize), AllocError> {
        let elastic = self.arena(id).is_ok() && self.extents.is_elastic(id.index());
        let candidates = self
            .extents
            .iter()
            .enumerate()
            .filter_map(|(index, extent)| extent.as_ref().map(|extent| (index, extent)))
            .filter(|(index, _)| self.extent_matches_source(*index, source))
            .filter(|(_, extent)| extent.belongs_to(id) && extent.kind == kind && !extent.revoked)
            .filter_map(|(index, extent)| {
                plan_allocation(extent.watermark, 1usize << extent.size_bits, size_bits)
                    .map(|(_, watermark)| (index, extent.size_bits, watermark))
            });
        let selected = if elastic {
            candidates.min_by_key(|(_, extent_bits, _)| *extent_bits)
        } else {
            candidates.into_iter().next()
        };
        selected
            .map(|(index, _, watermark)| (index, watermark))
            .ok_or(AllocError::ArenaTooSmall {
                size_bits,
                required: 1usize << size_bits,
            })
    }

    pub fn allocate_in(
        &mut self,
        id: TaskArenaId,
        blueprint: sel4::ObjectBlueprint,
    ) -> Result<crate::root_cspace::RootSlot<sel4::cap_type::Unspecified>, AllocError> {
        self.allocate_in_kind(id, blueprint, ExtentKind::Static)
    }

    /// Physical base and remaining room of one extent this arena may draw from.
    ///
    /// Read from the record the allocator keeps, never predicted: a caller
    /// certifying where its pages will land must use the same paddr and
    /// watermark the next retype will.
    fn extent_placement(
        &self,
        id: TaskArenaId,
        kind: ExtentKind,
        size_bits: usize,
        source: ExtentSource,
    ) -> Option<(usize, usize, usize)> {
        let (index, _) = self
            .extent_for_allocation(id, kind, size_bits, source)
            .ok()?;
        let extent = self.extents.get(index).and_then(Option::as_ref)?;
        let size = 1usize << size_bits;
        let start = extent.watermark.checked_next_multiple_of(size)?;
        let capacity = 1usize << extent.size_bits;
        let room = capacity.checked_sub(start)? / size;
        Some((index, extent.paddr.checked_add(start)?, room))
    }

    fn allocate_in_kind(
        &mut self,
        id: TaskArenaId,
        blueprint: sel4::ObjectBlueprint,
        kind: ExtentKind,
    ) -> Result<crate::root_cspace::RootSlot<sel4::cap_type::Unspecified>, AllocError> {
        self.arena(id)?;
        self.ensure_allocation_descriptors(1)?;
        self.allocation_position()?;
        let size_bits = blueprint.physical_size_bits();
        let (extent_index, watermark) =
            self.extent_for_allocation(id, kind, size_bits, ExtentSource::Common)?;
        let slot = self.take_slot()?;
        let parent = self.extents[extent_index]
            .expect("selected extent exists")
            .parent;
        if let Err(error) = crate::root_cspace::retype(parent, &blueprint, slot, 1) {
            self.slots.release(slot);
            return Err(AllocError::Retype { size_bits, error });
        }
        if let Err(error) = self.push_allocation(
            id,
            Some(extent_index),
            ArenaAllocation::new(slot, size_bits, false, false),
        ) {
            let root = sel4::init_thread::slot::CNODE.cap();
            let _ = root
                .absolute_cptr(sel4::CPtr::from_bits(slot as _))
                .delete();
            self.slots.release(slot);
            return Err(error);
        }
        let bytes = 1usize << size_bits;
        self.extents.update(extent_index, |extent| {
            extent.watermark = watermark;
            extent.objects += 1;
            extent.bytes += bytes;
        });
        self.objects_allocated += 1;
        self.live_objects += 1;
        self.bytes_allocated += bytes;
        self.live_bytes += bytes;
        Ok(crate::root_cspace::RootSlot::from_address(slot))
    }

    pub fn allocate_fixed_in<T: sel4::CapTypeForObjectOfFixedSize>(
        &mut self,
        id: TaskArenaId,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        Ok(self.allocate_in(id, T::object_blueprint())?.cast())
    }

    pub fn allocate_variable_in<T: sel4::CapTypeForObjectOfVariableSize>(
        &mut self,
        id: TaskArenaId,
        size_bits: usize,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        Ok(self.allocate_in(id, T::object_blueprint(size_bits))?.cast())
    }

    pub fn reserve_slot_in<T: sel4::CapType>(
        &mut self,
        id: TaskArenaId,
    ) -> Result<crate::root_cspace::RootSlot<T>, AllocError> {
        self.arena(id)?;
        self.ensure_allocation_descriptors(1)?;
        self.allocation_position()?;
        let slot = self.take_slot()?;
        if let Err(error) =
            self.push_allocation(id, None, ArenaAllocation::new(slot, 0, false, false))
        {
            self.slots.release(slot);
            return Err(error);
        }
        Ok(crate::root_cspace::RootSlot::from_address(slot))
    }

    /// Root CSlots an ordinary consumer may take.
    ///
    /// Reservation-held slots are withheld here rather than at `take_slot`,
    /// so every funding predicate that asks "can this be paid for" — task
    /// construction, preserved splits, private provisioning, the elastic
    /// inventory — sees the same reduced figure, and a guarantee cannot be
    /// spent by an unrelated consumer between admission and redemption.
    pub fn free_slots(&self) -> usize {
        self.slots
            .free()
            .saturating_sub(self.reserved_slots())
            .saturating_sub(self.operational_floor(self.operational_resources.slots))
    }

    /// Whether `free` descriptors are available to an ordinary consumer, with
    /// reservation-held and floor records withheld exactly as
    /// [`Self::allocation_descriptors_free`] withholds them.
    fn has_allocation_descriptors(&self, free: usize) -> bool {
        free == 0 || self.allocation_descriptors_free() >= free
    }

    pub fn ensure_allocation_descriptors(&mut self, free: usize) -> Result<(), AllocError> {
        #[cfg(test)]
        self.allocations
            .provision_host(MAX_TASK_ALLOCATIONS.max(free), AllocationRecord::EMPTY);
        // A figure out of step with the records could never be satisfied by
        // growing the table, so refuse before mapping a page.
        if self.allocations.out_of_step() {
            return Err(Self::private_record_error());
        }
        while !self.has_allocation_descriptors(free) {
            if self
                .allocations
                .len()
                .checked_add(segmented::Segmented::<AllocationRecord>::entries_per_page())
                .is_none_or(|capacity| capacity >= u32::MAX as usize)
            {
                return Err(Self::private_record_error());
            }
            if self.allocations.needs_directory_page() {
                let page = self.map_metadata_page()?;
                // SAFETY: the ledger retains this fresh page exclusively as the
                // allocation table's next directory page.
                unsafe { self.allocations.add_directory_page(page) }
                    .map_err(|()| Self::private_record_error())?;
            }
            let page = self.map_metadata_page()?;
            // SAFETY: page ownership is retained by the metadata ledger and no
            // other record table references this freshly mapped page.
            unsafe { self.allocations.append(page) }.map_err(|()| Self::private_record_error())?;
        }
        Ok(())
    }

    pub fn infrastructure_owned_bytes(&self) -> usize {
        self.infrastructure.owned_bytes()
    }

    /// Hand a private region the record tracking which spans own a leaf table.
    ///
    /// Funded like every other metadata table: a page is taken from the same
    /// infrastructure allocator and stays owned by it, so the record's address
    /// is stable for the region's whole life. A window wider than one record
    /// addresses is refused here rather than silently tracked in part.
    pub(crate) fn acquire_leaf_spans(
        &mut self,
        spans: usize,
    ) -> Result<leaf_spans::LeafSpanBits, AllocError> {
        if spans == 0 || spans > leaf_spans::MAX_WINDOW_SPANS {
            return Err(AllocError::PrivateRegionSpans {
                spans,
                limit: leaf_spans::MAX_WINDOW_SPANS,
            });
        }
        if self.leaf_spans.available() == 0 {
            #[cfg(test)]
            self.leaf_spans
                .provision_host(leaf_spans::LeafSpanStore::entries_per_page());
            if self.leaf_spans.available() == 0 {
                let page = self.map_metadata_page()?;
                // SAFETY: page ownership is retained by the metadata ledger and
                // no other record table references this freshly mapped page.
                unsafe { self.leaf_spans.append(page) }
                    .map_err(|()| Self::private_record_error())?;
            }
        }
        self.leaf_spans
            .acquire(spans)
            .ok_or_else(Self::private_record_error)
    }

    /// Return a reclaimed region's span record for the next region.
    pub(crate) fn release_leaf_spans(&mut self, bits: leaf_spans::LeafSpanBits) {
        self.leaf_spans.release(bits);
    }

    /// Span records this allocator can hand out without new backing.
    pub(crate) fn leaf_span_records_free(&self) -> usize {
        self.leaf_spans.available()
    }

    pub fn allocation_descriptor_capacity(&self) -> usize {
        self.allocations.len()
    }

    /// Allocation descriptors an ordinary consumer may take, with every
    /// reservation-held record withheld for the reason [`Self::free_slots`]
    /// withholds slots.
    pub fn allocation_descriptors_free(&self) -> usize {
        let owned = self.allocations.owned();
        #[cfg(test)]
        assert_eq!(
            owned,
            self.allocations.recount_owned(),
            "recount: owned allocation records"
        );
        self.allocations
            .len()
            .saturating_sub(owned)
            .saturating_sub(self.reserved_descriptors())
            .saturating_sub(self.operational_floor(self.operational_resources.descriptors))
    }

    #[cfg(any(slime_private_stress, slime_private_rollback, test))]
    pub(crate) fn reserve_stress_descriptors(&mut self, leave_free: usize) -> usize {
        let count = self
            .allocation_descriptors_free()
            .saturating_sub(leave_free);
        let mut remaining = count;
        for index in 0..self.allocations.len() {
            if remaining == 0 {
                break;
            }
            if self.allocations[index].owner == u16::MAX {
                // Reserved metadata has no capability and belongs to no task arena.
                self.allocations
                    .update(index, |record| record.owner = u16::MAX - 1);
                remaining -= 1;
            }
        }
        count
    }

    #[cfg(any(slime_private_stress, slime_private_rollback, test))]
    pub(crate) fn release_stress_descriptors(&mut self) {
        for index in 0..self.allocations.len() {
            if self.allocations[index].owner == u16::MAX - 1 {
                self.allocations.set(index, AllocationRecord::EMPTY);
            }
        }
    }

    /// Grow retained-prefix storage before any split or prefix publication.
    pub fn ensure_preserved_records(&mut self, free: usize) -> Result<(), AllocError> {
        // Host tests exercise the same growth path with the historical
        // envelope, so a test that fills it still observes a real refusal.
        #[cfg(test)]
        self.preserved.provision_host(global_backing::MAX_PRESERVED);
        while self.preserved.capacity() - self.preserved.len() < free {
            let page = self
                .map_metadata_page()
                .map_err(|_| AllocError::UntypedTableFull {
                    limit: self.preserved.capacity(),
                    declared: self.preserved.len() + free,
                })?;
            // SAFETY: the metadata ledger retains this fresh page exclusively
            // for retained-prefix records.
            unsafe {
                self.preserved
                    .records
                    .append(page, preserved::PreservedRecord::EMPTY)
            }
            .map_err(|()| AllocError::NoKernelUntyped)?;
        }
        Ok(())
    }

    pub fn ensure_extent_descriptors(&mut self, free: usize) -> Result<(), AllocError> {
        #[cfg(test)]
        self.extents
            .provision_host(MAX_TASK_EXTENTS.max(free), None);
        // As for allocation descriptors: no page could bring a figure out of
        // step back to its records.
        if self.extents.out_of_step() {
            return Err(AllocError::ArenaTableFull {
                limit: MAX_TASK_EXTENTS,
            });
        }
        while self.extent_descriptors_free() < free {
            if self
                .extents
                .len()
                .checked_add(segmented::Segmented::<Option<ExtentRecord>>::entries_per_page())
                .is_none_or(|capacity| capacity >= u32::MAX as usize)
            {
                return Err(AllocError::ArenaTableFull {
                    limit: self.extents.len(),
                });
            }
            if self.extents.needs_directory_page() {
                let page = self.map_metadata_page()?;
                // SAFETY: the ledger retains this fresh page exclusively as the
                // extent table's next directory page.
                unsafe { self.extents.add_directory_page(page) }
                    .map_err(|()| AllocError::NoKernelUntyped)?;
            }
            let page = self.map_metadata_page()?;
            // SAFETY: the metadata ledger retains this fresh page exclusively
            // for this table until the root stops.
            unsafe { self.extents.append(page) }.map_err(|()| AllocError::NoKernelUntyped)?;
        }
        Ok(())
    }

    pub fn extent_descriptor_capacity(&self) -> usize {
        self.extents.len()
    }

    pub fn extent_descriptors_free(&self) -> usize {
        let present = self.extents.present();
        #[cfg(test)]
        assert_eq!(
            present,
            self.extents.recount_present(),
            "recount: present extent records"
        );
        self.extents
            .len()
            .saturating_sub(present)
            .saturating_sub(self.operational_floor(self.operational_resources.extents))
    }

    pub fn release_slot(&mut self, slot: usize) -> bool {
        self.physical.remove(slot);
        self.slots.release(slot)
    }

    pub fn arena_slot_count(&self, id: TaskArenaId) -> Result<usize, AllocError> {
        Ok(self.arena(id)?.slot_len)
    }

    /// Live kernel objects and bytes belonging to one incarnation's extents.
    pub fn arena_usage(&self, id: TaskArenaId) -> Result<(usize, usize, usize), AllocError> {
        let slots = self.arena(id)?.slot_len;
        let mut objects = 0;
        let mut bytes = 0;
        for extent in self
            .extents
            .iter()
            .flatten()
            .filter(|extent| extent.belongs_to(id))
        {
            objects += extent.objects as usize;
            bytes += extent.bytes;
        }
        Ok((slots, objects, bytes))
    }

    pub fn provision_private_backing(
        &mut self,
        id: TaskArenaId,
        quota: usize,
    ) -> Result<(), AllocError> {
        self.private_arena(id)?;
        provision_private_backing_with(quota, |request| match request {
            PrivateBackingRequest::Extent { kind, size_bits } => {
                self.provision_extent(id, size_bits, kind).map(|_| ())
            }
            PrivateBackingRequest::Slots { count } => self.provision_private_slots(id, count),
        })
    }

    #[cfg(slime_private_stress)]
    pub(crate) fn provision_stress_private_backing(
        &mut self,
        id: TaskArenaId,
        quota: usize,
        attempt: usize,
    ) -> Result<(), AllocError> {
        let guard = if attempt == 0 {
            Some(self.begin_task_arena(MAX_PRIVATE_EXTENT_BYTES.trailing_zeros() as usize + 1)?)
        } else {
            None
        };
        let reused_before = self.extents_reused;
        let mut data = 0;
        let result = provision_private_backing_with(quota, |request| match request {
            PrivateBackingRequest::Extent { kind, size_bits } => {
                self.provision_extent(id, size_bits, kind)?;
                if kind == ExtentKind::PrivateData {
                    data += 1;
                    if data <= 3
                        && let Some(guard) = guard
                    {
                        self.provision_extent(guard, size_bits + 1, ExtentKind::Static)?;
                    }
                }
                Ok(())
            }
            PrivateBackingRequest::Slots { count } => self.provision_private_slots(id, count),
        });
        if let Some(guard) = guard {
            self.release_task_arena(guard)?;
            crate::diagnostic_println!(
                "SLIME_MEM stress fragmented guards=4 bytes=16777216 released=1"
            );
        }
        let mut previous = None;
        let mut discontinuities = 0;
        for extent in self
            .extents
            .iter()
            .flatten()
            .filter(|extent| extent.belongs_to(id) && extent.kind == ExtentKind::PrivateData)
        {
            if previous.is_some_and(|address| address + MAX_PRIVATE_EXTENT_BYTES != extent.paddr) {
                discontinuities += 1;
            }
            previous = Some(extent.paddr);
        }
        let reused = self.extents_reused - reused_before;
        crate::diagnostic_println!(
            "SLIME_MEM stress backing attempt={attempt} data_extents={data} discontinuities={discontinuities} reused={reused}"
        );
        result
    }

    pub fn provision_private_slots(
        &mut self,
        id: TaskArenaId,
        count: usize,
    ) -> Result<(), AllocError> {
        self.private_arena(id)?;
        self.ensure_allocation_descriptors(count)?;
        self.ensure_root_slots(count)?;
        #[cfg(slime_private_stress)]
        {
            let attempt =
                STRESS_SLOT_ATTEMPT.swap(usize::MAX, core::sync::atomic::Ordering::Relaxed);
            if attempt != usize::MAX {
                let actual = self.free_slots();
                let reserved = self.slots.reserve_stress_pressure(count.saturating_sub(1));
                let effective = self.free_slots();
                crate::diagnostic_println!(
                    "SLIME_MEM stress construction case=slots attempt={attempt} actual={actual} effective={effective} required={count} reserved={reserved}"
                );
            }
        }
        let refused = count > self.allocation_descriptors_free() || count > self.free_slots();
        #[cfg(slime_private_stress)]
        self.slots.release_stress_pressure();
        if refused {
            return Err(Self::private_record_error());
        }
        for _ in 0..count {
            let slot = self.take_slot()?;
            let position =
                match self.push_allocation(id, None, ArenaAllocation::new(slot, 0, true, true)) {
                    Ok(position) => position,
                    Err(error) => {
                        self.slots.release(slot);
                        return Err(error);
                    }
                };
            self.push_reusable(id, position)?;
        }
        Ok(())
    }

    fn take_private_slot(
        &mut self,
        id: TaskArenaId,
        kind: PrivateObjectKind,
        size_bits: usize,
        source: ExtentSource,
    ) -> Result<(usize, usize, usize, bool, bool), AllocError> {
        // A released record still names the extent it was retyped from, so it
        // may only be reused for the same source; otherwise a guaranteed page
        // could be served by a record backed from the common pool.
        if let Some(position) = self.pop_reusable_from(id, kind, Some(size_bits), source)? {
            let (mapped, extent) = self.allocations.update(position, |record| {
                let mapped = record.allocation.is_mapped();
                record
                    .allocation
                    .set_private_state(kind, size_bits, false, mapped);
                (mapped, record.extent as usize)
            });
            return Ok((position, extent, 0, true, mapped));
        }
        let extent_kind = if kind == PrivateObjectKind::LeafTable {
            ExtentKind::PrivateTables
        } else {
            ExtentKind::PrivateData
        };
        let (extent, watermark) = self.extent_for_allocation(id, extent_kind, size_bits, source)?;
        let position = self
            .pop_reusable(id, PrivateObjectKind::Empty, None)?
            .ok_or_else(Self::private_record_error)?;
        self.allocations.update(position, |record| {
            record.extent = extent as u32;
            record
                .allocation
                .set_private_state(kind, size_bits, false, false);
        });
        Ok((position, extent, watermark, false, false))
    }

    /// A large frame occupies its entire data extent. Only a reusable, unmapped
    /// frame can be revoked here: committed and in-flight mappings remain owned.
    fn recycle_private_large_frame<K: crate::private_memory::PrivateMemoryKernel>(
        &mut self,
        id: TaskArenaId,
        kernel: &mut K,
    ) -> Result<(), AllocError> {
        let Some(position) = self.pop_reusable(id, PrivateObjectKind::LargeFrame, None)? else {
            return Ok(());
        };
        let record = self.allocations[position];
        let extent_index = record.extent as usize;
        let result = (|| {
            let extent = self
                .extents
                .get(extent_index)
                .and_then(Option::as_ref)
                .filter(|extent| {
                    extent.belongs_to(id)
                        && !extent.revoked
                        && extent.kind == ExtentKind::PrivateData
                        && extent.size_bits == record.allocation.size_bits()
                        && extent.objects == 1
                        && extent.bytes == 1usize << extent.size_bits
                        && !record.allocation.is_mapped()
                })
                .ok_or_else(Self::private_record_error)?;
            kernel
                .revoke(extent.parent)
                .map_err(|error| AllocError::ArenaCleanup {
                    slot: extent.parent.bits() as usize,
                    error,
                })
        })();
        if let Err(error) = result {
            self.push_reusable(id, position)?;
            return Err(error);
        }
        let (objects, bytes) = self.extents.update(extent_index, |extent| {
            let held = (extent.objects, extent.bytes);
            extent.watermark = 0;
            extent.objects = 0;
            extent.bytes = 0;
            held
        });
        self.live_objects -= objects as usize;
        self.live_bytes -= bytes;
        self.allocations.update(position, |record| {
            record.extent = PRIVATE_EXTENT_NONE;
            record
                .allocation
                .set_private_state(PrivateObjectKind::Empty, 0, true, false);
        });
        self.push_reusable(id, position)
    }

    pub(crate) fn acquire_private_in<K: crate::private_memory::PrivateMemoryKernel>(
        &mut self,
        id: TaskArenaId,
        kind: PrivateObjectKind,
        blueprint: sel4::ObjectBlueprint,
        source: ExtentSource,
        kernel: &mut K,
    ) -> Result<PrivateAllocation, AllocError> {
        debug_assert!(kind != PrivateObjectKind::Empty);
        self.private_arena(id)?;
        if kind == PrivateObjectKind::Granule {
            self.recycle_private_large_frame(id, kernel)?;
        }
        #[cfg(slime_private_fail_second_allocation)]
        if fail_private_allocation(kind, self.private_arena(id)?.in_flight_granules) {
            return Err(AllocError::Retype {
                size_bits: blueprint.physical_size_bits(),
                error: sel4::Error::NotEnoughMemory,
            });
        }
        let size_bits = blueprint.physical_size_bits();
        let (position, extent_index, watermark, reused, mapped) =
            self.take_private_slot(id, kind, size_bits, source)?;
        let slot = self.allocations[position].allocation.slot();
        if !reused {
            let parent = self.extents[extent_index]
                .expect("private extent exists")
                .parent;
            if let Err(error) = kernel.retype(parent, &blueprint, slot) {
                self.allocations.update(position, |record| {
                    record.extent = PRIVATE_EXTENT_NONE;
                    record
                        .allocation
                        .set_private_state(PrivateObjectKind::Empty, 0, true, false);
                });
                self.push_reusable(id, position)?;
                return Err(AllocError::Retype { size_bits, error });
            }
            let bytes = 1usize << size_bits;
            self.extents.update(extent_index, |extent| {
                extent.watermark = watermark;
                extent.objects += 1;
                extent.bytes += bytes;
            });
            self.objects_allocated += 1;
            self.live_objects += 1;
            self.bytes_allocated += bytes;
            self.live_bytes += bytes;
        }
        Ok(PrivateAllocation {
            arena: id,
            position: position as u32,
            cap: sel4::cap::Unspecified::from_bits(slot as _),
            mapped,
        })
    }

    pub(crate) fn mark_private_in_flight(
        &mut self,
        id: TaskArenaId,
        allocation: PrivateAllocation,
        mapped: bool,
    ) -> Result<(), AllocError> {
        #[cfg(test)]
        {
            self.private_visits.mark += 1;
        }
        let position = self.private_record_position(id, &allocation)?;
        let kind = self.allocations[position].allocation.private_kind();
        let size_bits = self.allocations[position].allocation.size_bits();
        let head = self.private_arena(id)?.in_flight_head;
        self.allocations.update(position, |record| {
            record
                .allocation
                .set_private_state(kind, size_bits, false, mapped);
            record.allocation.set_in_flight(true);
            record.next_state = head;
        });
        let arena = self.arena_mut(id)?;
        arena.in_flight_head = position as u32;
        if kind == PrivateObjectKind::Granule {
            arena.in_flight_granules += 1;
        }
        Ok(())
    }

    pub fn commit_private_transaction(&mut self, id: TaskArenaId) -> Result<(), AllocError> {
        self.private_arena(id)?;
        loop {
            let head = self.private_arena(id)?.in_flight_head;
            if head == PRIVATE_STATE_NONE {
                return Ok(());
            }
            let position = head as usize;
            #[cfg(test)]
            {
                self.private_visits.commit += 1;
            }
            let record = self
                .allocations
                .get(position)
                .filter(|record| {
                    record.belongs_to(id)
                        && record.allocation.is_private()
                        && record.allocation.is_in_flight()
                        && !record.allocation.is_reusable()
                })
                .ok_or_else(Self::private_record_error)?;
            let next = record.next_state;
            let kind = record.allocation.private_kind();
            self.arenas[id.index()].in_flight_head = next;
            self.allocations.update(position, |record| {
                record.next_state = PRIVATE_STATE_NONE;
                record.allocation.set_in_flight(false);
            });
            if kind == PrivateObjectKind::Granule {
                self.arenas[id.index()].in_flight_granules -= 1;
            }
        }
    }

    pub(crate) fn unwind_private_transaction<K: crate::private_memory::PrivateMemoryKernel>(
        &mut self,
        id: TaskArenaId,
        kernel: &mut K,
    ) -> Result<(), AllocError> {
        self.private_arena(id)?;
        loop {
            let head = self.private_arena(id)?.in_flight_head;
            if head == PRIVATE_STATE_NONE {
                return Ok(());
            }
            let position = head as usize;
            #[cfg(test)]
            {
                self.private_visits.unwind += 1;
            }
            let record = self
                .allocations
                .get(position)
                .filter(|record| {
                    record.belongs_to(id)
                        && record.allocation.is_private()
                        && record.allocation.is_in_flight()
                        && !record.allocation.is_reusable()
                })
                .ok_or_else(Self::private_record_error)?;
            let next = record.next_state;
            let slot = record.allocation.slot();
            let kind = record.allocation.private_kind();
            let size_bits = record.allocation.size_bits();
            if kind != PrivateObjectKind::LeafTable {
                kernel
                    .unmap_frame(sel4::cap::UnspecifiedPage::from_bits(slot as _))
                    .map_err(|error| AllocError::ArenaCleanup { slot, error })?;
            }
            self.arenas[id.index()].in_flight_head = next;
            if kind == PrivateObjectKind::Granule {
                self.arenas[id.index()].in_flight_granules -= 1;
            }
            // A mapped leaf names one fixed VSpace span. Retain it as committed
            // ownership for that span rather than publishing it to the
            // kind-wide reusable pool, where another span could acquire the
            // same still-mapped capability and incorrectly skip `map_leaf`.
            let reusable = kind != PrivateObjectKind::LeafTable;
            self.allocations.update(position, |record| {
                record.next_state = PRIVATE_STATE_NONE;
                record.allocation.set_private_state(
                    kind,
                    size_bits,
                    reusable,
                    kind == PrivateObjectKind::LeafTable,
                );
            });
            if reusable {
                self.push_reusable(id, position)?;
            }
        }
    }

    pub(crate) fn reset_private_in(
        &mut self,
        id: TaskArenaId,
        allocation: PrivateAllocation,
    ) -> Result<(), AllocError> {
        #[cfg(test)]
        {
            self.private_visits.reset += 1;
        }
        let position = self.private_record_position(id, &allocation)?;
        self.allocations.update(position, |record| {
            let kind = record.allocation.private_kind();
            let size_bits = record.allocation.size_bits();
            record
                .allocation
                .set_private_state(kind, size_bits, true, false);
        });
        self.push_reusable(id, position)
    }

    /// Revoke every backing extent before returning any task-owned CSlot.
    /// Completed revokes are recorded so a later failure is retryable exactly once.
    pub fn release_task_arena(&mut self, id: TaskArenaId) -> Result<usize, AllocError> {
        let released = self.arena(id)?.slot_len;
        self.arenas[id.index()].releasing = true;
        let root = sel4::init_thread::slot::CNODE.cap();
        for index in 0..self.extents.len() {
            let Some(extent) = self.extents[index] else {
                continue;
            };
            if !extent.belongs_to(id) || extent.revoked {
                continue;
            }
            let parent_slot = extent.parent.bits() as usize;
            // A reclamation whose revoke does not complete must keep the
            // holder's ownership rather than advertise capacity the machine
            // has not recovered; this injection makes that path observable.
            #[cfg(slime_private_conservation)]
            if elastic::inject_arena_revoke_failure() {
                self.arenas[id.index()].releasing = false;
                return Err(AllocError::ArenaCleanup {
                    slot: parent_slot,
                    error: sel4::Error::IllegalOperation,
                });
            }
            root.absolute_cptr(sel4::CPtr::from_bits(parent_slot as _))
                .revoke()
                .map_err(|error| AllocError::ArenaCleanup {
                    slot: parent_slot,
                    error,
                })?;
            self.live_objects = self.live_objects.saturating_sub(extent.objects as usize);
            self.live_bytes = self.live_bytes.saturating_sub(extent.bytes);
            self.extents.update(index, |record| {
                record.revoked = true;
                record.objects = 0;
                record.bytes = 0;
            });
        }
        self.arenas[id.index()].reusable_heads = [PRIVATE_STATE_NONE; 4];
        self.arenas[id.index()].in_flight_head = PRIVATE_STATE_NONE;
        self.arenas[id.index()].in_flight_granules = 0;
        for index in 0..self.allocations.len() {
            let record = self.allocations[index];
            if !record.belongs_to(id) {
                continue;
            }
            let slot = record.allocation.slot();
            root.absolute_cptr(sel4::CPtr::from_bits(slot as _))
                .delete()
                .map_err(|error| AllocError::ArenaCleanup { slot, error })?;
            self.slots.release(slot);
            self.physical.remove(slot);
            self.allocations.set(index, AllocationRecord::EMPTY);
            self.allocation_search_start = self.allocation_search_start.min(index);
        }
        for index in 0..self.extents.len() {
            if self.extents[index].is_some_and(|extent| extent.belongs_to(id)) {
                self.settle_returned_extent(index);
            }
        }
        self.mapping_tables.forget(id);
        self.elastic_quarantine[id.index()] = elastic::Quarantine::EMPTY;
        self.arenas[id.index()] = ArenaRecord::empty();
        self.extents.reset_arena(id.index());
        Ok(released)
    }

    pub fn allocate_device_frame(
        &mut self,
        paddr: usize,
    ) -> Result<crate::root_cspace::RootSlot<sel4::cap_type::Granule>, AllocError> {
        if !paddr.is_multiple_of(GRANULE_BYTES) {
            return Err(AllocError::UnalignedDeviceFrame { paddr });
        }
        let (region_index, region) = self
            .devices
            .iter()
            .take(self.device_len)
            .enumerate()
            .find_map(|(index, region)| {
                let region = region.as_ref()?;
                region
                    .contains(paddr, GRANULE_BYTES)
                    .then_some((index, *region))
            })
            .ok_or(AllocError::NoDeviceUntyped { paddr })?;
        let target = (paddr - region.paddr) / GRANULE_BYTES;
        let count = target
            .checked_sub(region.retyped)
            .and_then(|count| count.checked_add(1))
            .ok_or(AllocError::DeviceFramePassed { paddr })?;

        // Preflight the exact sparse walk before advancing the kernel untyped's
        // watermark. Each completed chunk leaves only its last slot live, so
        // the next allocation sees the original pool plus one virtual anchor.
        // A fragmented or exhausted pool is therefore refused before the first
        // retype rather than leaving an unreachable consumed prefix behind.
        let mut planned = 0;
        let mut planned_anchor = None;
        while planned < count {
            let chunk_len = device_retype_plan(
                region.retyped + planned,
                target,
                self.free_slots(),
                planned_anchor.is_some(),
            )
            .map(|(_, batch)| batch)
            .ok_or(AllocError::SlotsExhausted {
                allocated: self.slots_allocated,
            })?;
            let first = self
                .slots
                .first_contiguous(chunk_len, planned_anchor)
                .ok_or(AllocError::SlotsExhausted {
                    allocated: self.slots_allocated,
                })?;
            planned += chunk_len;
            planned_anchor = Some(first + chunk_len - 1);
        }
        if self.physical.len >= MAX_PHYSICAL_PROVENANCE {
            return Err(AllocError::ProvenanceTableFull {
                limit: MAX_PHYSICAL_PROVENANCE,
            });
        }

        let mut completed = 0;
        let mut anchor = None;
        let root = sel4::init_thread::slot::CNODE.cap();

        while completed < count {
            let chunk_len = device_retype_plan(
                region.retyped + completed,
                target,
                self.free_slots(),
                anchor.is_some(),
            )
            .map(|(_, batch)| batch)
            .ok_or(AllocError::SlotsExhausted {
                allocated: self.slots_allocated,
            })?;
            let (first, reused) = self
                .slots
                .allocate_contiguous(chunk_len, self.slots_allocated)?;
            let last = first + chunk_len - 1;
            let final_chunk = completed + chunk_len == count;
            if final_chunk && let Err(error) = self.physical.insert(last, paddr) {
                for slot in first..first + chunk_len {
                    self.slots.release(slot);
                }
                return Err(error);
            }
            if let Err(error) = crate::root_cspace::retype(
                region.cap,
                &sel4::FrameObjectType::GRANULE.blueprint(),
                first,
                chunk_len,
            ) {
                if final_chunk {
                    self.physical.remove(last);
                }
                for slot in first..first + chunk_len {
                    self.slots.release(slot);
                }
                return Err(AllocError::Retype {
                    size_bits: sel4::FrameObjectType::GRANULE.bits(),
                    error,
                });
            }
            self.slots_allocated += chunk_len;
            self.slots_reused += reused;
            self.objects_allocated += chunk_len;
            self.live_objects += chunk_len;
            self.bytes_allocated += chunk_len * GRANULE_BYTES;
            self.live_bytes += chunk_len * GRANULE_BYTES;

            // Keep one child while advancing to the next chunk. If every cap
            // disappeared, seL4 would reset the device untyped's free index to
            // zero and the next retype would recreate the prefix instead of
            // continuing toward the requested physical page.
            if let Some(slot) = anchor.take() {
                root.absolute_cptr(sel4::CPtr::from_bits(slot as sel4::CPtrBits))
                    .delete()
                    .map_err(|error| AllocError::DeviceCleanup { slot, error })?;
                self.slots.release(slot);
                self.live_objects -= 1;
                self.live_bytes -= GRANULE_BYTES;
            }
            for slot in first..last {
                root.absolute_cptr(sel4::CPtr::from_bits(slot as sel4::CPtrBits))
                    .delete()
                    .map_err(|error| AllocError::DeviceCleanup { slot, error })?;
                self.slots.release(slot);
                self.live_objects -= 1;
                self.live_bytes -= GRANULE_BYTES;
            }
            anchor = Some(last);
            completed += chunk_len;
        }
        if let Some(region) = self.devices[region_index].as_mut() {
            region.retyped += count;
        }

        self.last_paddr = paddr;
        Ok(crate::root_cspace::RootSlot::from_address(anchor.unwrap()))
    }

    fn regions(&self) -> &[Option<UntypedRegion>] {
        self.untypeds.get(..self.untyped_len).unwrap_or(&[])
    }
}

#[cfg(test)]
impl ObjectAllocator {
    fn reset_private_record_visits(&mut self) {
        self.private_visits = PrivateRecordVisits::default();
    }

    fn private_record_visits(&self) -> PrivateRecordVisits {
        self.private_visits
    }

    /// Present extent records and owned allocation records read since the
    /// last reset, however they were reached.
    pub(crate) fn record_reads(&self) -> usize {
        self.extents.reads() + self.allocations.reads()
    }

    pub(crate) fn reset_record_reads(&self) {
        self.extents.set_reads(0);
        self.allocations.set_reads(0);
    }

    /// Run `check` without counting what it reads: the recounts a test build
    /// compares maintained figures with are not part of serving a request.
    fn uncounted<R>(&self, check: impl FnOnce(&Self) -> R) -> R {
        let (extents, allocations) = (self.extents.reads(), self.allocations.reads());
        let result = check(self);
        self.extents.set_reads(extents);
        self.allocations.set_reads(allocations);
        result
    }

    /// Register an arena already owning `slots` root CSlots, for host tests.
    ///
    /// `begin_task_arena` retypes its static extent, which needs a live
    /// kernel; this records the same arena identity and slot ownership without
    /// one. The arena holds no allocation or extent record, so
    /// `release_task_arena` reports its slot count without invoking the
    /// kernel.
    pub(crate) fn arena_owning_slots_for_test(&mut self, slots: usize) -> TaskArenaId {
        self.extents.provision_host(MAX_TASK_EXTENTS, None);
        self.allocations
            .provision_host(MAX_TASK_ALLOCATIONS, AllocationRecord::EMPTY);
        let index = self
            .arenas
            .iter()
            .position(|arena| !arena.active)
            .expect("test arena table has room");
        let serial = self.next_arena_serial;
        self.next_arena_serial = self.next_arena_serial.wrapping_add(1).max(1);
        self.extents.reset_arena(index);
        self.arenas[index] = ArenaRecord {
            serial,
            active: true,
            slot_len: slots,
            ..ArenaRecord::empty()
        };
        self.arenas[index].id(index)
    }
}

#[cfg(test)]
mod tests {
    use super::elastic::{ElasticRefusal, ElasticRequest};
    use super::guarantee_vault::{
        MAX_RESERVATION_BATCH, MAX_RESERVATIONS, ReservationBacking, ReservationError,
        ReservationRequest, ReservedKind,
    };
    use super::{
        AllocError, AllocationRecord, ArenaAllocation, ArenaPlan, ArenaRecord, ExtentKind,
        ExtentRecord, ExtentSource, GRANULE_BYTES, KERNEL_ROOT_CNODE_SLOTS,
        LARGE_DESCRIPTOR_TABLES, MAX_PHYSICAL_PROVENANCE, MAX_PLANNED_PRIVATE_PAGES,
        MAX_PLANNED_PRIVATE_SPANS, MAX_PLANNED_STATIC_ALLOCATIONS, MAX_PRIVATE_EXTENT_BYTES,
        MAX_PRIVATE_EXTENT_PAGES, MAX_TASK_ALLOCATIONS, MAX_TASK_ARENAS, MAX_TASK_EXTENTS,
        ObjectAllocator, PLANNED_QUALIFICATION_HOLDERS, PRIVATE_EXTENT_NONE, PRIVATE_STATE_NONE,
        PROVENANCE_SLOTS, PrivateBackingLayout, PrivateBackingRequest, PrivateObjectKind,
        PrivateRecordVisits, ProvenanceTable, SlotPool, TaskArenaId, TaskBackingCapacity,
        TaskStaticBacking, UntypedRegion, device_retype_plan, max_admissible_private_allocations,
        max_admissible_private_extents, plan_allocation, plan_task_backing,
        provision_private_backing_with, task_backing_extents_fit_in,
        task_static_backing_from_records, widest_private_allocations, widest_private_extents,
    };
    use crate::private_memory::{PrivateMemoryKernel, Region, Table};
    use sel4::CapTypeForObjectOfFixedSize;
    extern crate std;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum KernelRequest {
        Retype { slot: usize, size_bits: usize },
        MapFrame { slot: usize, vaddr: usize },
        MapLeaf { slot: usize, vaddr: usize },
        UnmapFrame { slot: usize },
        Revoke { slot: usize },
    }

    #[derive(Default)]
    struct RecordingPrivateKernel {
        requests: Vec<KernelRequest>,
        fail_retype_at: Option<usize>,
        fail_map_frame_at: Option<usize>,
        fail_unmap_at: Option<usize>,
        fail_revoke: bool,
        retypes: usize,
        frame_maps: usize,
        unmaps: usize,
    }

    impl PrivateMemoryKernel for RecordingPrivateKernel {
        fn revoke(&mut self, parent: sel4::cap::Untyped) -> Result<(), sel4::Error> {
            self.requests.push(KernelRequest::Revoke {
                slot: parent.bits() as usize,
            });
            if self.fail_revoke {
                Err(sel4::Error::NotEnoughMemory)
            } else {
                Ok(())
            }
        }

        fn retype(
            &mut self,
            _parent: sel4::cap::Untyped,
            blueprint: &sel4::ObjectBlueprint,
            slot: usize,
        ) -> Result<(), sel4::Error> {
            self.retypes += 1;
            self.requests.push(KernelRequest::Retype {
                slot,
                size_bits: blueprint.physical_size_bits(),
            });
            if self.fail_retype_at == Some(self.retypes) {
                Err(sel4::Error::NotEnoughMemory)
            } else {
                Ok(())
            }
        }

        fn map_frame(
            &mut self,
            frame: sel4::cap::UnspecifiedPage,
            _vspace: sel4::cap::VSpace,
            vaddr: usize,
            _rights: sel4::CapRights,
            _attrs: sel4::VmAttributes,
        ) -> Result<(), sel4::Error> {
            self.frame_maps += 1;
            self.requests.push(KernelRequest::MapFrame {
                slot: frame.bits() as usize,
                vaddr,
            });
            if self.fail_map_frame_at == Some(self.frame_maps) {
                Err(sel4::Error::NotEnoughMemory)
            } else {
                Ok(())
            }
        }

        fn map_leaf(
            &mut self,
            table: sel4::cap::UnspecifiedIntermediateTranslationTable,
            _ty: sel4::TranslationTableObjectType,
            _vspace: sel4::cap::VSpace,
            vaddr: usize,
            _attrs: sel4::VmAttributes,
        ) -> Result<(), sel4::Error> {
            self.requests.push(KernelRequest::MapLeaf {
                slot: table.bits() as usize,
                vaddr,
            });
            Ok(())
        }

        fn unmap_frame(&mut self, frame: sel4::cap::UnspecifiedPage) -> Result<(), sel4::Error> {
            self.unmaps += 1;
            self.requests.push(KernelRequest::UnmapFrame {
                slot: frame.bits() as usize,
            });
            if self.fail_unmap_at == Some(self.unmaps) {
                Err(sel4::Error::NotEnoughMemory)
            } else {
                Ok(())
            }
        }
    }

    fn setup_private_growth_fixture_for(quota: usize) -> (ObjectAllocator, TaskArenaId) {
        let mut allocator = ObjectAllocator::empty();
        allocator.extents.provision_host(MAX_TASK_EXTENTS, None);
        allocator.slots = SlotPool::new(1024..KERNEL_ROOT_CNODE_SLOTS).unwrap();
        allocator.arenas[0] = ArenaRecord {
            serial: 1,
            active: true,
            ..ArenaRecord::empty()
        };
        let id = allocator.arenas[0].id(0);
        let mut extent_position = 0;
        provision_private_backing_with(quota, |request| match request {
            PrivateBackingRequest::Extent { kind, size_bits } => {
                let slot = allocator.take_slot()?;
                let mut extent =
                    ExtentRecord::new(sel4::cap::Untyped::from_bits(slot as _), size_bits);
                extent.assign(id.index(), id.serial, kind);
                allocator.extents.set(extent_position, Some(extent));
                extent_position += 1;
                Ok(())
            }
            PrivateBackingRequest::Slots { count } => allocator.provision_private_slots(id, count),
        })
        .unwrap();
        allocator.reset_private_record_visits();
        (allocator, id)
    }

    fn setup_private_growth_fixture() -> (ObjectAllocator, TaskArenaId) {
        setup_private_growth_fixture_for(512)
    }

    /// Physical provenance is retained for a live frame, dropped when the frame
    /// is released, and refused rather than lost when the table is full.
    ///
    /// The third arm is why this exists. This table replaced a
    /// `[usize; KERNEL_ROOT_CNODE_SLOTS]` array whose 2 MB of `.bss` spent 512 root
    /// CSlots and made an admissible generation unbootable, and the array's one
    /// virtue was that it could not fill. A bounded table can, and the *only*
    /// acceptable behaviour there is to fail closed: a frame whose physical base
    /// the root cannot recover, silently mapped from a stale or absent record,
    /// would put some other frame's address in a device descriptor and let the
    /// device touch memory nothing granted it.
    ///
    /// Driven through the table rather than through `ObjectAllocator`, whose
    /// every allocation path needs a live kernel to retype against; the seL4
    /// gates cover the join. The reuse arm is the one that would catch a
    /// `release_slot` that forgot to free its entry: a root allocating and
    /// releasing DMA frames in a loop must not exhaust a table sized to the
    /// live population.
    #[test]
    fn physical_provenance_is_freed_on_release_and_fails_closed_when_full() {
        const PAGE: usize = 4096;
        let mut table = ProvenanceTable::new();

        // An allocated frame's address is retrievable; an unrecorded slot's is
        // not, so `None` means "the root does not own this" rather than zero.
        assert_eq!(table.insert(7, 0x4000_0000), Ok(()));
        assert_eq!(table.get(7), Some(0x4000_0000));
        assert_eq!(table.get(8), None);

        // A released frame's address is gone. Answering from a stale record
        // would hand a device an address the root no longer owns.
        assert!(table.remove(7));
        assert_eq!(table.get(7), None);
        assert!(!table.remove(7));
        assert_eq!(table.len, 0);

        // Colliding slots stay individually findable and individually
        // removable: `PROVENANCE_SLOTS` apart is the same probe start, so
        // removing the first must not strand the second behind an empty
        // position. This is the property that lets deletion avoid tombstones.
        let (a, b, c) = (5, 5 + PROVENANCE_SLOTS, 5 + 2 * PROVENANCE_SLOTS);
        for (index, slot) in [a, b, c].into_iter().enumerate() {
            assert_eq!(table.insert(slot, index * PAGE), Ok(()));
        }
        assert!(table.remove(a));
        assert_eq!(table.get(b), Some(PAGE));
        assert_eq!(table.get(c), Some(2 * PAGE));
        assert!(table.remove(b));
        assert_eq!(table.get(c), Some(2 * PAGE));
        assert!(table.remove(c));
        assert_eq!(table.len, 0);

        // Full to its declared bound, then refused. Not dropped, not
        // overwritten: the record the caller would have read is still the one
        // it gets, and the new frame's allocation fails.
        for slot in 0..MAX_PHYSICAL_PROVENANCE {
            assert_eq!(table.insert(slot, slot * PAGE), Ok(()), "slot {slot}");
        }
        assert_eq!(table.len, MAX_PHYSICAL_PROVENANCE);
        assert_eq!(
            table.insert(MAX_PHYSICAL_PROVENANCE, 0xdead_0000),
            Err(AllocError::ProvenanceTableFull {
                limit: MAX_PHYSICAL_PROVENANCE
            })
        );
        assert_eq!(table.get(MAX_PHYSICAL_PROVENANCE), None);
        // And every prior record survived the refusal.
        for slot in 0..MAX_PHYSICAL_PROVENANCE {
            assert_eq!(table.get(slot), Some(slot * PAGE), "slot {slot}");
        }

        // A full table that releases one frame accepts one more, which is what
        // makes long-running reuse bounded by the live population rather than
        // by the number of frames the root has ever allocated.
        assert!(table.remove(0));
        assert_eq!(table.insert(MAX_PHYSICAL_PROVENANCE, 0x9000_0000), Ok(()));
        assert_eq!(table.get(MAX_PHYSICAL_PROVENANCE), Some(0x9000_0000));

        // Re-recording a live slot overwrites in place rather than consuming a
        // second position, so a pool that reissued an index still answers with
        // that index's current frame.
        assert_eq!(table.len, MAX_PHYSICAL_PROVENANCE);
        assert_eq!(table.insert(MAX_PHYSICAL_PROVENANCE, 0xa000_0000), Ok(()));
        assert_eq!(table.len, MAX_PHYSICAL_PROVENANCE);
        assert_eq!(table.get(MAX_PHYSICAL_PROVENANCE), Some(0xa000_0000));
    }

    #[test]
    fn sparse_device_retype_is_chunked_without_spending_the_root_cspace() {
        assert_eq!(device_retype_plan(0, 0, 3_000, false), Some((1, 1)));
        assert_eq!(device_retype_plan(0, 255, 3_000, false), Some((1, 256)));
        assert_eq!(device_retype_plan(0, 256, 3_000, false), Some((2, 256)));
        assert_eq!(device_retype_plan(0, 0x101, 3_000, false), Some((2, 256)));
        assert_eq!(device_retype_plan(7, 6, 3_000, false), None);

        assert_eq!(device_retype_plan(0, 20_517, 3_000, false), Some((81, 256)));
        assert_eq!(device_retype_plan(0, 261, 255, false), Some((2, 255)));
        assert_eq!(device_retype_plan(255, 261, 255, true), Some((1, 7)));
        assert_eq!(device_retype_plan(0, 0, 0, false), None);
        assert_eq!(device_retype_plan(0, 1, 1, true), None);
    }
    #[test]
    fn sparse_device_preflight_models_the_live_anchor_without_mutating_slots() {
        let mut slots = SlotPool::new(100..108).unwrap();
        for expected in 100..106 {
            let (allocated, _) = slots.allocate(0).unwrap();
            assert_eq!(allocated, expected);
        }
        assert!(slots.release(100));
        assert!(slots.release(102));
        assert!(slots.release(104));

        assert_eq!(slots.first_contiguous(1, None), Some(100));
        assert_eq!(slots.first_contiguous(1, Some(100)), Some(102));
        assert_eq!(slots.first_contiguous(2, None), Some(106));
        assert_eq!(slots.first_contiguous(2, Some(106)), None);
        assert_eq!(slots.live, 3);
    }

    #[test]
    fn allocation_is_aligned_to_object_size() {
        assert_eq!(plan_allocation(0, 1 << 20, 12), Some((0, 4096)));
        assert_eq!(plan_allocation(4096, 1 << 20, 14), Some((16384, 32768)));
    }

    #[test]
    fn alignment_loss_can_exhaust_a_region() {
        assert_eq!(plan_allocation(4096, 1 << 14, 14), None);
        assert_eq!(plan_allocation(4096, 1 << 14, 12), Some((4096, 8192)));
    }

    #[test]
    fn exact_fit_is_allowed_and_full_region_is_not() {
        assert_eq!(plan_allocation(0, 1 << 12, 12), Some((0, 4096)));
        assert_eq!(plan_allocation(4096, 1 << 12, 12), None);
    }

    #[test]
    fn runtime_plan_matches_provisioning_layout() {
        for quota in [0, 1, 511, 512, 513, 1024, 16_384, 32_768, 65_536] {
            let layout = PrivateBackingLayout::for_pages(quota);
            let plan = plan_task_backing(quota).unwrap();
            let spans = quota.div_ceil(MAX_PRIVATE_EXTENT_PAGES);
            assert_eq!(layout.private_pages, plan.private_pages);
            assert_eq!(layout.spans, plan.data_extents);
            assert_eq!(layout.extent_parent_slots() + 1, plan.extent_descriptors);
            assert_eq!(layout.allocation_descriptors, plan.allocation_descriptors);
            assert_eq!(
                layout.allocation_descriptors + layout.extent_parent_slots() + 1,
                plan.required_cslots
            );
            assert_eq!(plan.payload_bytes, quota * GRANULE_BYTES);
            assert_eq!(plan.page_table_bytes, spans * GRANULE_BYTES);
            assert_eq!(
                plan.reserved_bytes,
                spans * (MAX_PRIVATE_EXTENT_BYTES + GRANULE_BYTES)
            );
            assert_eq!(
                plan.alignment_waste,
                spans * MAX_PRIVATE_EXTENT_BYTES - quota * GRANULE_BYTES
            );
        }

        assert_eq!(
            plan_task_backing(16_384),
            Some(super::TaskBackingPlan {
                private_pages: 16_384,
                data_extents: 32,
                extent_descriptors: 65,
                allocation_descriptors: 16_448,
                required_cslots: 16_513,
                reserved_bytes: 67_239_936,
                payload_bytes: 67_108_864,
                page_table_bytes: 131_072,
                alignment_waste: 0,
            })
        );
    }

    #[test]
    fn private_provisioning_stops_at_first_failure() {
        for quota in [0, 3, 512] {
            let mut expected = [None; 4];
            let mut request_count = 0;
            provision_private_backing_with(quota, |request| {
                expected[request_count] = Some(request);
                request_count += 1;
                Ok(())
            })
            .unwrap();
            for failing in 0..request_count {
                let mut actual = [None; 4];
                let mut called = 0;
                let error = provision_private_backing_with(quota, |request| {
                    actual[called] = Some(request);
                    let current = called;
                    called += 1;
                    if current == failing {
                        Err(AllocError::NoKernelUntyped)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                assert_eq!(error, AllocError::NoKernelUntyped);
                assert_eq!(called, failing + 1);
                assert_eq!(actual[..called], expected[..called]);
            }
        }
    }

    #[test]
    fn runtime_capacity_rejects_each_reservation_shortfall() {
        let plan = plan_task_backing(512).unwrap();
        let exact = TaskBackingCapacity {
            plan,
            static_backing: TaskStaticBacking {
                allocation_descriptors: 8,
                reserved_bytes: 16_384,
            },
            holders: 1,
            cslots_available: 525,
            allocation_descriptors_available: 522,
            extent_descriptors_available: 3,
            ordinary_bytes_available: 2_117_632,
            ordinary_layout: Ok(()),
            root_image_bytes: 0,
            root_stack_bytes: 0,
            root_heap_bytes: 0,
        };
        assert_eq!(exact.requirements().unwrap().cslots, 525);
        assert!(exact.fits());
        assert!(
            !TaskBackingCapacity {
                cslots_available: 524,
                ..exact
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                allocation_descriptors_available: 521,
                ..exact
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                extent_descriptors_available: 2,
                ..exact
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                ordinary_bytes_available: 2_117_631,
                ..exact
            }
            .fits()
        );
    }

    #[test]
    fn backing_slots_scale_with_quota_and_cover_segmented_shapes() {
        assert_eq!(PrivateBackingLayout::for_quota(0).allocation_descriptors, 0);
        assert_eq!(
            PrivateBackingLayout::for_quota(8).allocation_descriptors,
            10
        );
        assert_eq!(
            PrivateBackingLayout::for_quota(512).allocation_descriptors,
            514
        );
        assert_eq!(
            PrivateBackingLayout::for_quota(2048).allocation_descriptors,
            2056
        );
        assert_eq!(
            PrivateBackingLayout::for_quota(crate::private_memory::MAX_REGION_PAGES)
                .allocation_descriptors,
            crate::private_memory::MAX_REGION_PAGES
                + 2 * crate::private_memory::MAX_REGION_PAGES.div_ceil(MAX_PRIVATE_EXTENT_PAGES)
        );
    }

    /// A quota's root-CSlot cost is its descriptors *plus* one slot per
    /// extent, measured against what provisioning actually takes from the
    /// pool rather than restated from the layout.
    ///
    /// The two must agree because generation admission adds this cost before
    /// any child starts.
    #[test]
    fn quota_root_slot_cost_counts_every_extent_parent() {
        // On its own large stack, as every allocator-holding test here is:
        // the record tables are megabytes and a default test stack holds no
        // `ObjectAllocator` at all.
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                // One allocator across every quota, each with its own arena,
                // measured as a delta -- which is what the per-holder
                // admission term is anyway.
                let mut allocator = ObjectAllocator::empty();
                allocator.extents.provision_host(MAX_TASK_EXTENTS, None);
                allocator.slots = SlotPool::new(1024..KERNEL_ROOT_CNODE_SLOTS).unwrap();
                let mut extent_position = 0;
                for (index, quota) in [0, 1, 8, 511, 512, 513, usize::MAX].into_iter().enumerate() {
                    let layout = PrivateBackingLayout::for_quota(quota);
                    allocator.arenas[index] = ArenaRecord {
                        serial: index as u32 + 1,
                        active: true,
                        ..ArenaRecord::empty()
                    };
                    let id = allocator.arenas[index].id(index);
                    let before = allocator.free_slots();
                    let extents_before = extent_position;
                    // `provision_extent`'s retype needs a live kernel, so the
                    // extent arm takes its slot directly and records the
                    // extent; the slot accounting under test is unchanged.
                    provision_private_backing_with(quota, |request| match request {
                        PrivateBackingRequest::Extent { kind, size_bits } => {
                            let slot = allocator.take_slot()?;
                            let mut extent = ExtentRecord::new(
                                sel4::cap::Untyped::from_bits(slot as _),
                                size_bits,
                            );
                            extent.assign(id.index(), id.serial, kind);
                            allocator.extents.set(extent_position, Some(extent));
                            extent_position += 1;
                            Ok(())
                        }
                        PrivateBackingRequest::Slots { count } => {
                            allocator.provision_private_slots(id, count)
                        }
                    })
                    .unwrap();
                    let consumed = before - allocator.free_slots();
                    assert_eq!(
                        consumed,
                        layout.allocation_descriptors + layout.extent_parent_slots(),
                        "quota {quota} consumed {consumed} root CSlots"
                    );
                    assert_eq!(
                        extent_position - extents_before,
                        layout.extent_parent_slots()
                    );
                }
                // Nonzero quotas retain one data extent and one table extent.
                assert_eq!(PrivateBackingLayout::for_quota(0).extent_parent_slots(), 0);
                assert_eq!(PrivateBackingLayout::for_quota(1).extent_parent_slots(), 2);
                assert_eq!(
                    PrivateBackingLayout::for_quota(511).extent_parent_slots(),
                    2
                );
                assert_eq!(
                    PrivateBackingLayout::for_quota(512).extent_parent_slots(),
                    2
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn freed_root_slot_is_the_next_slot_reused() {
        let mut slots = SlotPool::new(100..104).unwrap();
        assert_eq!(slots.allocate(0), Ok((100, false)));
        assert_eq!(slots.allocate(1), Ok((101, false)));
        assert!(slots.release(100));
        assert_eq!(slots.allocate(2), Ok((100, true)));
        assert_eq!(slots.live, 2);
    }

    #[test]
    fn bounded_live_slots_cross_the_old_lifetime_watermark() {
        let mut slots = SlotPool::new(10..14).unwrap();
        for issued in 0..80 {
            let (slot, reused) = slots.allocate(issued).unwrap();
            assert_eq!(slot, 10);
            assert_eq!(reused, issued != 0);
            assert!(slots.release(slot));
        }
        assert_eq!(slots.live, 0);
    }

    #[test]
    fn arena_plan_accounts_for_alignment() {
        let mut plan = ArenaPlan::new();
        plan.add_size_bits(12).unwrap();
        plan.add_size_bits(14).unwrap();
        assert_eq!(plan.required_bytes(), 32 * 1024);
        assert_eq!(plan.required_size_bits(), Some(15));
    }

    #[test]
    fn arena_release_model_returns_same_parent_space() {
        let mut parent_available = true;
        let first_parent = if core::mem::replace(&mut parent_available, false) {
            7
        } else {
            0
        };
        parent_available = true;
        let second_parent = if core::mem::replace(&mut parent_available, false) {
            7
        } else {
            0
        };
        assert_eq!(first_parent, second_parent);
    }

    #[test]
    fn large_capacity_plans_are_segmented_and_honest() {
        const PAGES_64_MIB: usize = 64 * 1024 * 1024 / 4096;
        const PAGES_256_MIB: usize = 256 * 1024 * 1024 / 4096;
        let sixty_four = plan_task_backing(PAGES_64_MIB).unwrap();
        assert_eq!(sixty_four.data_extents, 32);
        assert_eq!(sixty_four.payload_bytes, 64 * 1024 * 1024);
        assert_eq!(sixty_four.alignment_waste, 0);
        assert_eq!(sixty_four.page_table_bytes, 32 * 4096);

        let holder = plan_task_backing(PAGES_256_MIB).unwrap();
        assert_eq!(holder.data_extents, 128);
        assert_eq!(holder.reserved_bytes, 256 * 1024 * 1024 + 128 * 4096);
        let four_reserved = holder.reserved_bytes * 4;
        assert_eq!(four_reserved, 1_075_838_976);

        let current = plan_task_backing(MAX_PRIVATE_EXTENT_PAGES).unwrap();
        assert_eq!(current.data_extents, 1);
        assert_eq!(current.reserved_bytes, MAX_PRIVATE_EXTENT_BYTES + 4096);
        assert!(plan_task_backing(MAX_PLANNED_PRIVATE_PAGES + 1).is_none());
        // Grouping table extents keeps alignment overhead bounded per holder,
        // rather than discarding almost a large frame for every data span.
        let mut two_gib = [Some(UntypedRegion {
            cap: sel4::cap::Untyped::from_bits(1),
            paddr: 0x8000_0000,
            size_bits: 31,
            watermark: 128 * 1024 * 1024,
        })];
        assert!(task_backing_extents_fit_in(
            &mut two_gib,
            holder,
            TaskStaticBacking {
                allocation_descriptors: 520,
                reserved_bytes: 4 * 1024 * 1024,
            },
            4
        ));
        let mut regions = [Some(UntypedRegion {
            cap: sel4::cap::Untyped::from_bits(1),
            paddr: 0x8000_0000,
            size_bits: 32,
            watermark: 128 * 1024 * 1024,
        })];
        assert!(task_backing_extents_fit_in(
            &mut regions,
            holder,
            TaskStaticBacking {
                allocation_descriptors: 520,
                reserved_bytes: 4 * 1024 * 1024,
            },
            4
        ));
    }

    #[test]
    fn four_holder_capacity_refuses_every_real_resource_shortfall() {
        const PAGES_256_MIB: usize = 256 * 1024 * 1024 / 4096;
        let plan = plan_task_backing(PAGES_256_MIB).unwrap();
        let static_backing = TaskStaticBacking {
            allocation_descriptors: 8,
            reserved_bytes: 16_384,
        };
        let mut capacity = TaskBackingCapacity {
            plan,
            static_backing,
            holders: 4,
            cslots_available: usize::MAX,
            allocation_descriptors_available: usize::MAX,
            extent_descriptors_available: usize::MAX,
            ordinary_bytes_available: usize::MAX,
            ordinary_layout: Ok(()),
            root_image_bytes: 0,
            root_stack_bytes: 1024 * 1024,
            root_heap_bytes: 512 * 1024,
        };
        let required = capacity.requirements().unwrap();
        assert_eq!(required.extent_descriptors, 257 * 4);
        capacity.cslots_available = required.cslots;
        capacity.allocation_descriptors_available = required.allocation_descriptors;
        capacity.extent_descriptors_available = required.extent_descriptors;
        capacity.ordinary_bytes_available = required.reserved_bytes;
        assert!(capacity.fits());
        assert!(
            !TaskBackingCapacity {
                cslots_available: required.cslots - 1,
                ..capacity
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                allocation_descriptors_available: required.allocation_descriptors - 1,
                ..capacity
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                extent_descriptors_available: required.extent_descriptors - 1,
                ..capacity
            }
            .fits()
        );
        assert!(
            !TaskBackingCapacity {
                ordinary_bytes_available: required.reserved_bytes - 1,
                ..capacity
            }
            .fits()
        );
        capacity.ordinary_layout = Err(super::LayoutLimit::Placement);
        capacity.ordinary_bytes_available = required.reserved_bytes;
        assert!(!capacity.fits());
    }

    #[test]
    fn capacity_rejects_fragmented_untyped_alignment_false_positive() {
        let plan = plan_task_backing(512).unwrap();
        let static_backing = TaskStaticBacking {
            allocation_descriptors: 8,
            reserved_bytes: 16_384,
        };
        let region = |slot: usize, size_bits: usize, watermark: usize| {
            Some(UntypedRegion {
                cap: sel4::cap::Untyped::from_bits(slot as _),
                paddr: (slot - 1) << 21,
                size_bits,
                watermark,
            })
        };
        let mut fragmented = [
            region(1, 21, GRANULE_BYTES),
            region(2, 21, GRANULE_BYTES),
            region(3, 21, GRANULE_BYTES),
        ];
        let ordinary_bytes_available: usize = fragmented
            .iter()
            .flatten()
            .map(UntypedRegion::remaining)
            .sum();
        assert!(ordinary_bytes_available >= plan.reserved_bytes + static_backing.reserved_bytes);
        assert!(!task_backing_extents_fit_in(
            &mut fragmented,
            plan,
            static_backing,
            1,
        ));

        let mut contiguous = [region(1, 23, 0)];
        assert!(task_backing_extents_fit_in(
            &mut contiguous,
            plan,
            static_backing,
            1,
        ));
    }

    #[test]
    fn capacity_replays_grouped_table_then_data_extent_order() {
        let plan = plan_task_backing(1024).unwrap();
        let static_backing = TaskStaticBacking {
            allocation_descriptors: 1,
            reserved_bytes: 1024 * 1024,
        };
        let region = |watermark| {
            Some(UntypedRegion {
                cap: sel4::cap::Untyped::from_bits(1),
                paddr: 0x8000_0000,
                size_bits: 23,
                watermark,
            })
        };
        let mut misleading = [region(GRANULE_BYTES)];
        assert!(task_backing_extents_fit_in(
            &mut misleading,
            plan,
            static_backing,
            1,
        ));

        let mut fitting = [region(0)];
        assert!(task_backing_extents_fit_in(
            &mut fitting,
            plan,
            static_backing,
            1,
        ));
    }
    #[test]
    fn static_backing_counts_aliases_and_excludes_private_records() {
        let id = TaskArenaId::from_raw(2, 7);
        let other = TaskArenaId::from_raw(3, 7);
        let stale = TaskArenaId::from_raw(2, 8);
        let record =
            |owner: TaskArenaId, extent: u32, allocation: ArenaAllocation| AllocationRecord {
                owner: owner.index as u16,
                extent,
                serial: owner.serial,
                allocation,
                next_state: PRIVATE_STATE_NONE,
            };
        let mut private_empty = ArenaAllocation::new(12, 0, true, true);
        private_empty.set_private_state(PrivateObjectKind::Empty, 0, true, false);
        let mut private_frame = ArenaAllocation::new(13, 12, true, true);
        private_frame.set_private_state(PrivateObjectKind::Granule, 12, true, false);
        let mut private_leaf = ArenaAllocation::new(14, 12, true, true);
        private_leaf.set_private_state(PrivateObjectKind::LeafTable, 12, true, true);
        let allocations = [
            record(id, 0, ArenaAllocation::new(10, 12, false, false)),
            record(
                id,
                PRIVATE_EXTENT_NONE,
                ArenaAllocation::new(11, 0, false, false),
            ),
            record(id, PRIVATE_EXTENT_NONE, private_empty),
            record(id, 1, private_frame),
            record(id, 2, private_leaf),
            record(other, 0, ArenaAllocation::new(15, 12, false, false)),
            record(stale, 0, ArenaAllocation::new(16, 12, false, false)),
        ];
        let static_extent = |owner: TaskArenaId, revoked: bool| ExtentRecord {
            parent: sel4::cap::Untyped::from_bits(1),
            paddr: 0,
            size_bits: 16,
            owner: owner.index as u16,
            serial: owner.serial,
            kind: ExtentKind::Static,
            active: true,
            revoked,
            watermark: 4096,
            objects: 1,
            bytes: 4096,
            origin: super::guarantee_vault::RESERVATION_NONE,
            split: false,
            children: [super::extent_buddy::NO_EXTENT; 2],
            link: super::record_tables::NO_LINK,
        };
        assert_eq!(
            task_static_backing_from_records(
                id,
                allocations.iter(),
                [Some(static_extent(id, false))].iter()
            ),
            Some(TaskStaticBacking {
                allocation_descriptors: 2,
                reserved_bytes: 65_536,
            })
        );
        assert!(task_static_backing_from_records(id, allocations.iter(), [].iter()).is_none());
        assert!(
            task_static_backing_from_records(
                id,
                allocations.iter(),
                [Some(static_extent(id, true))].iter()
            )
            .is_none()
        );
        assert!(
            task_static_backing_from_records(
                id,
                allocations.iter(),
                [
                    Some(static_extent(id, false)),
                    Some(static_extent(id, false))
                ]
                .iter()
            )
            .is_none()
        );
        let mut overflow = static_extent(id, false);
        overflow.size_bits = usize::BITS as usize;
        assert!(
            task_static_backing_from_records(id, allocations.iter(), [Some(overflow)].iter())
                .is_none()
        );
        let mut private_extent = static_extent(id, false);
        private_extent.kind = ExtentKind::PrivateData;
        assert!(
            task_static_backing_from_records(id, allocations.iter(), [Some(private_extent)].iter())
                .is_none()
        );
    }

    #[test]
    fn four_holders_include_static_descriptors_at_default_pool_boundary() {
        let plan = plan_task_backing(65_536).unwrap();
        let capacity = TaskBackingCapacity {
            plan,
            static_backing: TaskStaticBacking {
                allocation_descriptors: 1,
                reserved_bytes: 4096,
            },
            holders: 4,
            cslots_available: usize::MAX,
            allocation_descriptors_available: 262_657,
            extent_descriptors_available: plan.extent_descriptors * 4,
            ordinary_bytes_available: usize::MAX,
            ordinary_layout: Ok(()),
            root_image_bytes: 0,
            root_stack_bytes: 0,
            root_heap_bytes: 0,
        };
        let required = capacity.requirements().unwrap();
        assert_eq!(required.allocation_descriptors, 263_172);
        assert_eq!(
            required.allocation_descriptors - capacity.allocation_descriptors_available,
            515
        );
        assert!(!capacity.fits());
    }

    #[test]
    fn capacity_overflow_is_refused_and_zero_holders_are_empty() {
        let plan = plan_task_backing(1).unwrap();
        let capacity = TaskBackingCapacity {
            plan,
            static_backing: TaskStaticBacking {
                allocation_descriptors: usize::MAX,
                reserved_bytes: usize::MAX,
            },
            holders: 1,
            cslots_available: usize::MAX,
            allocation_descriptors_available: usize::MAX,
            extent_descriptors_available: usize::MAX,
            ordinary_bytes_available: usize::MAX,
            ordinary_layout: Ok(()),
            root_image_bytes: 0,
            root_stack_bytes: 0,
            root_heap_bytes: 0,
        };
        assert_eq!(capacity.requirements(), None);
        assert!(!capacity.fits());
        let multiplied = TaskBackingCapacity {
            static_backing: TaskStaticBacking {
                allocation_descriptors: 0,
                reserved_bytes: 0,
            },
            holders: usize::MAX,
            ..capacity
        };
        assert_eq!(multiplied.requirements(), None);
        assert!(!multiplied.fits());
        let zero = TaskBackingCapacity {
            holders: 0,
            cslots_available: 0,
            allocation_descriptors_available: 0,
            extent_descriptors_available: 0,
            ordinary_bytes_available: 0,
            ..capacity
        };
        assert_eq!(
            zero.requirements(),
            Some(super::TaskBackingRequirements {
                cslots: 0,
                allocation_descriptors: 0,
                extent_descriptors: 0,
                reserved_bytes: 0,
            })
        );
        assert!(zero.fits());
    }

    #[test]
    fn single_page_growth_visits_only_selected_records() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    512,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel::default();
                for page in 0..512 {
                    assert_eq!(
                        table.grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            1,
                            &mut kernel,
                        ),
                        Ok(page)
                    );
                }
                assert_eq!(region.base(), 0x1000_0000);
                assert_eq!(region.pages(), 512);
                assert_eq!(region.base_frames(), 512);
                assert_eq!(region.large_frames(), 0);
                assert_eq!(region.leaf_tables(), 1);
                assert_eq!(table.total_pages(), 512);
                assert_eq!(table.grants(), 512);
                assert_eq!(table.grown_pages(), 512);
                assert_eq!(
                    allocator.private_record_visits(),
                    PrivateRecordVisits {
                        reusable: 513,
                        mark: 513,
                        reset: 0,
                        commit: 513,
                        unwind: 0,
                    }
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::Retype { .. }))
                        .count(),
                    513
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    1
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapFrame { .. }))
                        .count(),
                    512
                );
                assert!(
                    !kernel
                        .requests
                        .iter()
                        .any(|request| matches!(request, KernelRequest::UnmapFrame { .. }))
                );
                let records: Vec<_> = allocator
                    .allocations
                    .iter()
                    .filter(|record| record.belongs_to(arena) && record.allocation.is_private())
                    .collect();
                assert_eq!(records.len(), 514);
                assert_eq!(
                    records
                        .iter()
                        .filter(
                            |record| record.allocation.private_kind() == PrivateObjectKind::Empty
                        )
                        .count(),
                    1
                );
                assert!(
                    records
                        .iter()
                        .filter(|record| {
                            record.allocation.private_kind() != PrivateObjectKind::Empty
                        })
                        .all(|record| record.allocation.is_mapped()
                            && !record.allocation.is_reusable())
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn private_state_indices_reject_wrong_ownership() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let valid = allocator.arenas[arena.index()].reusable_heads
                    [PrivateObjectKind::Empty as usize];
                let snapshot = allocator.allocations[valid as usize];
                allocator
                    .allocations
                    .update(valid as usize, |record| record.owner = 1);
                let mut kernel = RecordingPrivateKernel::default();
                assert!(matches!(
                    allocator.acquire_private_in(
                        arena,
                        PrivateObjectKind::Granule,
                        sel4::cap_type::Granule::object_blueprint(),
                        ExtentSource::Common,
                        &mut kernel,
                    ),
                    Err(AllocError::ArenaSlotTableFull {
                        limit: MAX_TASK_ALLOCATIONS,
                    })
                ));
                allocator.allocations.set(valid as usize, snapshot);
                assert_eq!(
                    allocator.arenas[arena.index()].reusable_heads
                        [PrivateObjectKind::Empty as usize],
                    valid
                );
                allocator.arenas[arena.index()].releasing = true;
                assert_eq!(
                    allocator.provision_private_backing(arena, 1),
                    Err(AllocError::UnknownArena(arena))
                );
                assert_eq!(
                    allocator.commit_private_transaction(arena),
                    Err(AllocError::UnknownArena(arena))
                );
                assert_eq!(
                    allocator.unwind_private_transaction(arena, &mut kernel),
                    Err(AllocError::UnknownArena(arena))
                );
                assert!(kernel.requests.is_empty());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// The descriptor tables must hold the widest admitted private population
    /// *and* every task's static backing at once. Sizing them as "four holders
    /// at the per-holder ceiling" leaves zero descriptors for the `init` and
    /// coordinator instances such a graph also runs, and the shortfall appears
    /// only as a spawn refused after earlier holders reserved their backing.
    #[test]
    fn large_descriptor_tables_cover_the_aggregate_plus_every_task_static_cost() {
        if LARGE_DESCRIPTOR_TABLES {
            assert_eq!(MAX_PLANNED_PRIVATE_SPANS, 128);
            assert!(MAX_PLANNED_STATIC_ALLOCATIONS >= 16);
            assert!(
                super::MAX_PLANNED_IMAGE_ALLOCATIONS >= crate::child_vspace::MAX_TOTAL_IMAGE_PAGES
            );
            assert_eq!(
                MAX_TASK_ALLOCATIONS,
                widest_private_allocations()
                    + super::MAX_PLANNED_IMAGE_ALLOCATIONS
                    + MAX_TASK_ARENAS * MAX_PLANNED_STATIC_ALLOCATIONS
                    + super::mapping_tables::RECORDS
            );
            assert_eq!(
                MAX_TASK_EXTENTS,
                MAX_TASK_ARENAS + widest_private_extents() + super::mapping_tables::RECORDS
            );
            // Both demands are covered: the aggregate a growth may actually
            // charge, and the four-holder plan the capacity report describes.
            // Neither dominates the other in general, so the bound is the max.
            assert!(MAX_TASK_ALLOCATIONS >= max_admissible_private_allocations());
            assert!(MAX_TASK_EXTENTS >= MAX_TASK_ARENAS + max_admissible_private_extents());
            let planned = plan_task_backing(MAX_PLANNED_PRIVATE_PAGES)
                .expect("the planner represents its own maximum");
            assert!(
                MAX_TASK_ALLOCATIONS
                    >= PLANNED_QUALIFICATION_HOLDERS * planned.allocation_descriptors
                        + PLANNED_QUALIFICATION_HOLDERS * MAX_PLANNED_STATIC_ALLOCATIONS,
                "the four-holder capacity report would answer fit=0 for want of \
                 descriptor table rather than platform resources"
            );
            assert!(MAX_TASK_EXTENTS >= PLANNED_QUALIFICATION_HOLDERS * planned.extent_descriptors);
            // Headroom beyond the holders themselves: a holder graph also runs
            // `init` and a coordinator, and a table sized to exactly N holders
            // refuses their spawn after the holders reserved their backing.
            assert!(
                MAX_TASK_ALLOCATIONS
                    - PLANNED_QUALIFICATION_HOLDERS * planned.allocation_descriptors
                    >= 2 * MAX_PLANNED_STATIC_ALLOCATIONS
            );
        }
    }

    #[test]
    fn failed_large_extent_revoke_retains_ownership_then_reaches_base_page_quota() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    512,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel {
                    fail_map_frame_at: Some(1),
                    ..Default::default()
                };
                assert!(
                    table
                        .grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            512,
                            &mut kernel
                        )
                        .is_err()
                );
                let position = allocator.arenas[arena.index()].reusable_heads
                    [PrivateObjectKind::LargeFrame as usize]
                    as usize;
                let extent_index = allocator.allocations[position].extent as usize;
                let parent = allocator.extents[extent_index].unwrap().parent;
                kernel.fail_map_frame_at = None;
                kernel.fail_revoke = true;
                for _ in 0..2 {
                    assert!(
                        table
                            .grow_with_kernel(
                                &mut allocator,
                                arena,
                                vspace,
                                &mut region,
                                1,
                                &mut kernel
                            )
                            .is_err()
                    );
                    assert_eq!(region.pages(), 0);
                    assert_eq!(table.total_pages(), 0);
                    assert_eq!(
                        allocator.allocations[position].allocation.private_kind(),
                        PrivateObjectKind::LargeFrame
                    );
                    assert!(allocator.allocations[position].allocation.is_reusable());
                    let extent = allocator.extents[extent_index].unwrap();
                    assert!(extent.belongs_to(arena));
                    assert_eq!(extent.objects, 1);
                    assert_eq!(extent.bytes, MAX_PRIVATE_EXTENT_BYTES);
                    assert_eq!(extent.watermark, MAX_PRIVATE_EXTENT_BYTES);
                    assert_eq!(extent.parent, parent);
                }
                kernel.fail_revoke = false;
                for page in 0..512 {
                    assert_eq!(
                        table.grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            1,
                            &mut kernel
                        ),
                        Ok(page)
                    );
                }
                assert_eq!(region.base_frames(), 512);
                assert_eq!(region.large_frames(), 0);
                assert_eq!(allocator.live_objects(), 513);
                assert_eq!(
                    allocator.live_bytes(),
                    MAX_PRIVATE_EXTENT_BYTES + GRANULE_BYTES
                );
                assert_eq!(allocator.extents[extent_index].unwrap().objects, 512);
                assert_eq!(allocator.extents[extent_index].unwrap().parent, parent);
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::Revoke { .. }))
                        .count(),
                    3
                );
                assert!(
                    kernel
                        .requests
                        .iter()
                        .filter_map(|request| match request {
                            KernelRequest::Revoke { slot } => Some(*slot),
                            _ => None,
                        })
                        .all(|slot| slot == parent.bits() as usize)
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn one_page_growth_and_failed_large_frames_are_both_counted() {
        const PAGES_256_MIB: usize = 256 * 1024 * 1024 / 4096;
        let holder = plan_task_backing(PAGES_256_MIB).unwrap();
        assert_eq!(holder.allocation_descriptors, PAGES_256_MIB + 256);
        assert_eq!(holder.required_cslots, holder.allocation_descriptors + 257);
        assert!(holder.required_cslots > 4096);
    }

    #[test]
    fn allocation_metadata_is_root_wide_and_compact() {
        assert!(core::mem::size_of::<ArenaAllocation>() <= 16);
        assert!(core::mem::size_of::<AllocationRecord>() <= 32);
        assert!(
            core::mem::size_of::<ArenaRecord>()
                < core::mem::size_of::<[ArenaAllocation; MAX_TASK_ALLOCATIONS]>()
        );
        let mut allocation = ArenaAllocation::new((1usize << 60) + 40, 21, true, false);
        allocation.set_private_state(PrivateObjectKind::LargeFrame, 21, true, true);
        assert_eq!(allocation.slot(), (1usize << 60) + 40);
        assert_eq!(allocation.private_kind(), PrivateObjectKind::LargeFrame);
        assert!(allocation.is_reusable());
        assert!(allocation.is_mapped());
    }

    /// The seL4 loader spends one root CSlot per page of the root image before
    /// the root runs, and it maps each segment's `memsz`, so the allocator's
    /// tables are charged whether they are initialized or zero-backed. Tables
    /// the booting kernel's own CNode cannot pay for make the image unbootable
    /// before admission is ever evaluated, so they must be sized against the
    /// kernel actually linked, not against the widest one supported. A
    /// quarter of the CSpace is the budget: the rest carries the product
    /// graph's own objects, which `admit_total_slots` then counts.
    #[test]
    fn allocator_state_fits_the_linked_kernels_root_cspace() {
        let image_slots = core::mem::size_of::<ObjectAllocator>().div_ceil(GRANULE_BYTES);
        assert!(
            image_slots * 4 <= KERNEL_ROOT_CNODE_SLOTS,
            "allocator state spends {image_slots} of {KERNEL_ROOT_CNODE_SLOTS} root CSlots"
        );
        assert_eq!(
            LARGE_DESCRIPTOR_TABLES,
            MAX_TASK_ALLOCATIONS > 4096,
            "table size must follow the kernel width, not a hand-set flag"
        );
        assert_eq!(
            MAX_TASK_EXTENTS > 3 * MAX_TASK_ARENAS,
            LARGE_DESCRIPTOR_TABLES
        );
    }

    #[test]
    fn only_in_flight_records_are_the_failed_transactions_own_objects() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    512,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel::default();
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1,
                        &mut kernel,
                    ),
                    Ok(0)
                );
                kernel.fail_retype_at = Some(kernel.retypes + 2);
                let error = table
                    .grow_with_kernel(&mut allocator, arena, vspace, &mut region, 2, &mut kernel)
                    .unwrap_err();
                assert!(matches!(
                    error,
                    crate::private_memory::GrowError::Frames { allocated: 1, .. }
                ));
                assert_eq!(region.pages(), 1);
                assert_eq!(region.base_frames(), 1);
                assert_eq!(region.leaf_tables(), 1);
                assert_eq!(table.total_pages(), 1);
                assert_eq!(table.grants(), 1);
                assert_eq!(
                    allocator.arenas[arena.index()].in_flight_head,
                    PRIVATE_STATE_NONE
                );
                assert_eq!(allocator.arenas[arena.index()].in_flight_granules, 0);
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::UnmapFrame { .. }))
                        .count(),
                    1
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn raised_window_rolls_back_partial_mapping_and_allocation_then_retries() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let quota = crate::private_memory::MAX_REGION_PAGES;
                if quota < 65_536 {
                    return;
                }
                let (mut allocator, arena) = setup_private_growth_fixture_for(65_536);
                let descriptors = allocator.allocation_descriptors_free();
                let original: std::vec::Vec<_> = allocator.allocations.iter().copied().collect();
                assert_eq!(allocator.reserve_stress_descriptors(1), descriptors - 1);
                assert_eq!(allocator.allocation_descriptors_free(), 1);
                allocator.release_stress_descriptors();
                assert_eq!(
                    allocator
                        .allocations
                        .iter()
                        .copied()
                        .collect::<std::vec::Vec<_>>(),
                    original
                );
                let slots = allocator.free_slots();
                assert_eq!(allocator.slots.reserve_stress_pressure(1), slots - 1);
                assert_eq!(allocator.free_slots(), 1);
                let (last, _) = allocator.slots.allocate(0).unwrap();
                assert_eq!(allocator.free_slots(), 0);
                assert!(allocator.slots.allocate(0).is_err());
                allocator.slots.release_stress_pressure();
                assert_eq!(allocator.free_slots(), slots - 1);
                assert!(allocator.slots.release(last));
                assert_eq!(allocator.free_slots(), slots);
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    65_536,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel::default();
                for (delta, previous) in [(1, 0), (511, 1)] {
                    assert_eq!(
                        table.grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            delta,
                            &mut kernel
                        ),
                        Ok(previous)
                    );
                }
                kernel.fail_map_frame_at = Some(kernel.frame_maps + 2);
                assert!(matches!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1024,
                        &mut kernel
                    ),
                    Err(crate::private_memory::GrowError::Frames { allocated: 512, .. })
                ));
                assert_eq!(region.pages(), 512);
                assert_eq!(table.total_pages(), 512);
                kernel.fail_map_frame_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1024,
                        &mut kernel
                    ),
                    Ok(512)
                );
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        65_534 - 1536,
                        &mut kernel
                    ),
                    Ok(1536)
                );
                kernel.fail_retype_at = Some(kernel.retypes + 2);
                assert!(matches!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        2,
                        &mut kernel
                    ),
                    Err(crate::private_memory::GrowError::Frames { allocated: 1, .. })
                ));
                assert_eq!(region.pages(), 65_534);
                assert_eq!(table.total_pages(), 65_534);
                kernel.fail_retype_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        2,
                        &mut kernel
                    ),
                    Ok(65_534)
                );
                assert_eq!(region.pages(), 65_536);
                assert_eq!(region.large_frames(), 126);
                assert_eq!(region.base_frames(), 1024);
                assert_eq!(region.leaf_tables(), 2);
                assert_eq!(table.total_pages(), 65_536);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn an_unwound_frame_stays_owned_and_typed_for_the_retry() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    512,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel {
                    fail_retype_at: Some(3),
                    ..RecordingPrivateKernel::default()
                };
                assert!(
                    table
                        .grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            2,
                            &mut kernel,
                        )
                        .is_err()
                );
                let retypes_after_failure = kernel.retypes;
                kernel.fail_retype_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        2,
                        &mut kernel,
                    ),
                    Ok(0)
                );
                assert_eq!(kernel.retypes, retypes_after_failure + 1);
                assert_eq!(region.pages(), 2);
                assert_eq!(region.leaf_tables(), 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn an_unwound_leaf_table_is_retained_mapped() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture();
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    512,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel {
                    fail_retype_at: Some(3),
                    ..RecordingPrivateKernel::default()
                };
                assert!(
                    table
                        .grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            2,
                            &mut kernel,
                        )
                        .is_err()
                );
                assert_eq!(region.pages(), 0);
                assert_eq!(region.leaf_tables(), 1);
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    1
                );
                kernel.fail_retype_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        2,
                        &mut kernel,
                    ),
                    Ok(0)
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    1
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn a_retained_mapped_leaf_stays_bound_to_its_span_across_retry_and_later_growth() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture_for(513);
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    513,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel {
                    // Retype and map the first span's leaf, then fail the first
                    // base-frame retype before any page can commit.
                    fail_retype_at: Some(2),
                    ..RecordingPrivateKernel::default()
                };

                assert!(
                    table
                        .grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            1,
                            &mut kernel,
                        )
                        .is_err()
                );
                assert_eq!((region.pages(), region.leaf_tables()), (0, 1));
                assert_eq!(table.total_pages(), 0);
                assert_eq!(table.grants(), 0);
                assert_eq!(
                    allocator.arenas[arena.index()].in_flight_head,
                    PRIVATE_STATE_NONE
                );
                assert_eq!(
                    allocator.arenas[arena.index()].reusable_heads
                        [PrivateObjectKind::LeafTable as usize],
                    PRIVATE_STATE_NONE,
                    "the mapped leaf must not enter the cross-span reusable pool"
                );
                let first_leaf = kernel
                    .requests
                    .iter()
                    .find_map(|request| match request {
                        KernelRequest::MapLeaf { slot, vaddr } => Some((*slot, *vaddr)),
                        _ => None,
                    })
                    .unwrap();

                kernel.fail_retype_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1,
                        &mut kernel,
                    ),
                    Ok(0)
                );
                assert_eq!((region.pages(), region.leaf_tables()), (1, 1));
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    1,
                    "retry in the original span must use its retained mapping"
                );

                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        512,
                        &mut kernel,
                    ),
                    Ok(1)
                );
                let leaves: Vec<_> = kernel
                    .requests
                    .iter()
                    .filter_map(|request| match request {
                        KernelRequest::MapLeaf { slot, vaddr } => Some((*slot, *vaddr)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(leaves.len(), 2);
                assert_eq!(leaves[0], first_leaf);
                assert_ne!(leaves[1].0, first_leaf.0);
                assert_eq!(leaves[1].1, region.base() + 512 * GRANULE_BYTES);
                assert_eq!(
                    (region.pages(), region.base_frames(), region.leaf_tables()),
                    (513, 513, 2)
                );
                assert_eq!(
                    (table.total_pages(), table.grown_pages(), table.grants()),
                    (513, 513, 2)
                );
                assert_eq!(
                    allocator.arenas[arena.index()].in_flight_head,
                    PRIVATE_STATE_NONE
                );
                assert_eq!(allocator.arenas[arena.index()].in_flight_granules, 0);
                assert_eq!(table.reclaim(&mut allocator, &mut region), 513);
                assert_eq!(
                    (region.pages(), region.base_frames(), region.leaf_tables()),
                    (0, 0, 0)
                );
                assert_eq!((table.total_pages(), table.reclaimed_pages()), (0, 513));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn mixed_large_and_base_growth_reuses_the_second_spans_leaf_table() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture_for(514);
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    514,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel::default();
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        513,
                        &mut kernel
                    ),
                    Ok(0)
                );
                assert_eq!(
                    (
                        region.large_frames(),
                        region.base_frames(),
                        region.leaf_tables()
                    ),
                    (1, 1, 1)
                );
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1,
                        &mut kernel
                    ),
                    Ok(513)
                );
                assert_eq!(
                    (region.pages(), region.base_frames(), region.leaf_tables()),
                    (514, 2, 1)
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    1
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn a_retained_leaf_in_a_later_span_is_reused_on_retry() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let (mut allocator, arena) = setup_private_growth_fixture_for(513);
                let mut table = Table::new();
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    513,
                    false,
                )
                .expect("host test window");
                let vspace = sel4::cap::VSpace::from_bits(7);
                let mut kernel = RecordingPrivateKernel::default();
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        512,
                        &mut kernel
                    ),
                    Ok(0)
                );
                kernel.fail_retype_at = Some(kernel.retypes + 2);
                assert!(
                    table
                        .grow_with_kernel(
                            &mut allocator,
                            arena,
                            vspace,
                            &mut region,
                            1,
                            &mut kernel
                        )
                        .is_err()
                );
                assert_eq!((region.pages(), region.leaf_tables()), (512, 1));
                let leaf_maps = kernel
                    .requests
                    .iter()
                    .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                    .count();
                assert_eq!(leaf_maps, 1);
                kernel.fail_retype_at = None;
                assert_eq!(
                    table.grow_with_kernel(
                        &mut allocator,
                        arena,
                        vspace,
                        &mut region,
                        1,
                        &mut kernel
                    ),
                    Ok(512)
                );
                assert_eq!((region.pages(), region.leaf_tables()), (513, 1));
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    leaf_maps
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    const LARGE_EXTENT_BITS: usize = MAX_PRIVATE_EXTENT_BYTES.trailing_zeros() as usize;
    const GRANULE_EXTENT_BITS: usize = GRANULE_BYTES.trailing_zeros() as usize;

    fn reservation_fixture() -> ObjectAllocator {
        let mut allocator = ObjectAllocator::empty();
        allocator.extents.provision_host(MAX_TASK_EXTENTS, None);
        allocator
            .allocations
            .provision_host(MAX_TASK_ALLOCATIONS, AllocationRecord::EMPTY);
        allocator.slots = SlotPool::new(1024..KERNEL_ROOT_CNODE_SLOTS).unwrap();
        allocator
    }

    /// Seed returned extent records, exactly as an elastic release leaves
    /// them: inactive, unreserved, owned by no arena. The fixture admits no
    /// ordinary untyped range, so a request these records cannot serve fails
    /// without a kernel — which is what makes "the reserved one was not
    /// taken" observable rather than inferred.
    fn seed_reusable_extents(
        allocator: &mut ObjectAllocator,
        kind: ExtentKind,
        size_bits: usize,
        count: usize,
    ) {
        for _ in 0..count {
            let slot = allocator.take_slot().expect("host test slot");
            let index = allocator
                .extents
                .iter()
                .position(Option::is_none)
                .expect("host test extent record");
            let mut extent = ExtentRecord::new(sel4::cap::Untyped::from_bits(slot as _), size_bits);
            extent.kind = kind;
            // Distinct aligned bases, as a real retype would produce: two
            // extents sharing one address would let overlapping placements
            // certify.
            extent.paddr = (index + 1) * MAX_PRIVATE_EXTENT_BYTES;
            allocator.extents.set(index, Some(extent));
        }
    }

    fn reserved_positions(allocator: &ObjectAllocator) -> Vec<usize> {
        allocator
            .extents
            .iter()
            .enumerate()
            .filter(|(_, extent)| extent.is_some_and(|extent| extent.is_reserved()))
            .map(|(index, _)| index)
            .collect()
    }

    fn data_request(size_bits: usize) -> ReservationRequest {
        ReservationRequest {
            kind: ReservedKind::Data,
            size_bits,
        }
    }

    #[test]
    fn a_reserved_extent_is_never_selected_by_ordinary_or_elastic_acquisition() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_backing(reservation, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                let reserved = reserved_positions(&allocator);
                assert_eq!(reserved.len(), 1);

                // Ordinary arena provisioning of the same size takes the
                // unreserved record.
                let arena = allocator.arena_owning_slots_for_test(0);
                let taken = allocator
                    .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                assert!(!reserved.contains(&taken));
                assert_eq!(
                    allocator
                        .extent_for_allocation(
                            arena,
                            ExtentKind::PrivateData,
                            LARGE_EXTENT_BITS,
                            ExtentSource::Common,
                        )
                        .map(|(index, _)| index),
                    Ok(taken)
                );

                // Only the reserved extent is left, so the next request is
                // refused instead of served from it.
                assert!(matches!(
                    allocator.provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData),
                    Err(AllocError::UntypedExhausted { .. })
                ));
                assert_eq!(reserved_positions(&allocator), reserved);

                // The elastic path refuses for the same reason: its inventory
                // does not see the reserved bytes, and its acquisition cannot
                // reach the record.
                let elastic = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(elastic).unwrap();
                let demand = ElasticRequest {
                    large_frames: 1,
                    base_pages: 0,
                    tables: 0,
                }
                .demand()
                .unwrap();
                assert!(matches!(
                    allocator.preflight_elastic(&demand),
                    Err(ElasticRefusal::Exhausted {
                        resource: "ordinary-bytes",
                        available: 0,
                        ..
                    })
                ));
                assert!(matches!(
                    allocator.acquire_elastic(elastic, &demand),
                    Err(AllocError::UntypedExhausted { .. })
                ));
                assert_eq!(reserved_positions(&allocator), reserved);
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap(),
                    ReservationBacking {
                        extents: 1,
                        bytes: MAX_PRIVATE_EXTENT_BYTES,
                        data_extents: 1,
                        table_extents: 0,
                        borrowed_extents: 0,
                        borrowed_bytes: 0,
                    }
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn reserved_backing_leaves_common_capacity_exactly_once() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    3,
                );
                let before = allocator.elastic_inventory();
                assert_eq!(before.bytes, 3 * MAX_PRIVATE_EXTENT_BYTES as u64);
                assert_eq!(allocator.reusable_extent_anchors(), 3);
                assert_eq!(allocator.reserved_extent_anchors(), 0);

                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_backing(
                        reservation,
                        &[
                            data_request(LARGE_EXTENT_BITS),
                            data_request(LARGE_EXTENT_BITS),
                        ],
                    )
                    .unwrap();

                let after = allocator.elastic_inventory();
                assert_eq!(after.bytes, MAX_PRIVATE_EXTENT_BYTES as u64);
                assert_eq!(allocator.reusable_extent_bytes(), MAX_PRIVATE_EXTENT_BYTES);
                assert_eq!(
                    allocator.reusable_private_extent_bytes(),
                    MAX_PRIVATE_EXTENT_BYTES
                );
                assert_eq!(allocator.active_extent_bytes(), 0);
                assert_eq!(
                    allocator.reserved_extent_bytes(),
                    2 * MAX_PRIVATE_EXTENT_BYTES
                );
                assert_eq!(allocator.reusable_extent_anchors(), 1);
                assert_eq!(allocator.reserved_extent_anchors(), 2);
                // Held, free and reserved are disjoint and complete: every
                // seeded byte appears in exactly one of the three.
                assert_eq!(
                    allocator.active_extent_bytes()
                        + allocator.reusable_extent_bytes()
                        + allocator.reserved_extent_bytes(),
                    3 * MAX_PRIVATE_EXTENT_BYTES
                );
                // A reserved record is not a free record either.
                assert_eq!(after.extents, before.extents);

                assert_eq!(allocator.close_reservation(reservation).unwrap(), 2);
                assert_eq!(allocator.elastic_inventory().bytes, before.bytes);
                assert_eq!(allocator.reserved_extent_bytes(), 0);
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), 3);
                assert_eq!(allocator.live_reservations(), 0);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn two_reservations_own_disjoint_backing() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    3,
                );
                let first = allocator.open_reservation().unwrap();
                let second = allocator.open_reservation().unwrap();
                assert_ne!(first.index(), second.index());
                allocator
                    .reserve_backing(first, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                let owned_by_first = reserved_positions(&allocator);
                allocator
                    .reserve_backing(
                        second,
                        &[
                            data_request(LARGE_EXTENT_BITS),
                            data_request(LARGE_EXTENT_BITS),
                        ],
                    )
                    .unwrap();
                let owned_by_second: Vec<usize> = reserved_positions(&allocator)
                    .into_iter()
                    .filter(|index| !owned_by_first.contains(index))
                    .collect();
                assert_eq!(owned_by_first.len(), 1);
                assert_eq!(owned_by_second.len(), 2);
                assert_eq!(allocator.reservation_backing(first).unwrap().extents, 1);
                assert_eq!(allocator.reservation_backing(second).unwrap().extents, 2);
                assert_eq!(allocator.live_reservations(), 2);

                // Closing one returns only its own backing.
                assert_eq!(allocator.close_reservation(first).unwrap(), 1);
                assert_eq!(
                    allocator.reservation_backing(second).unwrap(),
                    ReservationBacking {
                        extents: 2,
                        bytes: 2 * MAX_PRIVATE_EXTENT_BYTES,
                        data_extents: 2,
                        table_extents: 0,
                        borrowed_extents: 0,
                        borrowed_bytes: 0,
                    }
                );
                assert_eq!(reserved_positions(&allocator), owned_by_second);
                assert_eq!(allocator.reusable_extent_anchors(), 1);
                assert_eq!(
                    allocator.reservation_backing(first),
                    Err(ReservationError::UnknownReservation(first))
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn a_stale_reservation_identity_is_refused_by_every_entry_point() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                let stale = allocator.open_reservation().unwrap();
                assert_eq!(allocator.close_reservation(stale).unwrap(), 0);
                let live = allocator.open_reservation().unwrap();
                // The table position is reissued; the identity is not.
                assert_eq!(live.index(), stale.index());
                assert_ne!(live.serial(), stale.serial());

                assert_eq!(
                    allocator.reserve_backing(stale, &[data_request(LARGE_EXTENT_BITS)]),
                    Err(ReservationError::UnknownReservation(stale))
                );
                assert_eq!(
                    allocator.reservation_backing(stale),
                    Err(ReservationError::UnknownReservation(stale))
                );
                assert_eq!(
                    allocator.close_reservation(stale),
                    Err(ReservationError::UnknownReservation(stale))
                );
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.live_reservations(), 1);

                // The live identity at the same position still works.
                allocator
                    .reserve_backing(live, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                assert_eq!(allocator.reservation_backing(live).unwrap().extents, 1);

                // The identity table is bounded and refuses by name.
                let mut opened = Vec::new();
                while allocator.live_reservations() < MAX_RESERVATIONS {
                    opened.push(allocator.open_reservation().unwrap());
                }
                assert_eq!(
                    allocator.open_reservation(),
                    Err(ReservationError::TableFull {
                        limit: MAX_RESERVATIONS
                    })
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn reserved_data_and_table_backing_are_separately_owned() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateTables,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_backing(
                        reservation,
                        &[ReservationRequest {
                            kind: ReservedKind::Tables,
                            size_bits: GRANULE_EXTENT_BITS,
                        }],
                    )
                    .unwrap();
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap(),
                    ReservationBacking {
                        extents: 1,
                        bytes: GRANULE_BYTES,
                        data_extents: 0,
                        table_extents: 1,
                        borrowed_extents: 0,
                        borrowed_bytes: 0,
                    }
                );

                // The reserved table extent is the only granule record left,
                // so a task arena's table provisioning is refused while its
                // data provisioning is untouched.
                let arena = allocator.arena_owning_slots_for_test(0);
                assert!(matches!(
                    allocator.provision_extent(
                        arena,
                        GRANULE_EXTENT_BITS,
                        ExtentKind::PrivateTables
                    ),
                    Err(AllocError::UntypedExhausted { .. })
                ));
                assert!(
                    allocator
                        .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                        .is_ok()
                );
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap().bytes,
                    GRANULE_BYTES
                );
                assert_eq!(allocator.reserved_extent_anchors(), 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A reservation call that cannot complete returns the extents it already
    /// took, so a failure leaves the reservation and the pool exactly as the
    /// call found them. Backing taken by an earlier successful call stays.
    #[test]
    fn a_failed_reservation_rolls_back_its_own_prefix_only() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                assert!(matches!(
                    allocator.reserve_backing(reservation, &[data_request(LARGE_EXTENT_BITS); 3]),
                    Err(ReservationError::Backing(
                        AllocError::UntypedExhausted { .. }
                    ))
                ));
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap(),
                    ReservationBacking::default()
                );
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), 2);
                assert_eq!(
                    allocator.reusable_extent_bytes(),
                    2 * MAX_PRIVATE_EXTENT_BYTES
                );

                // A wider request than one call may own is refused by name,
                // before anything is taken.
                let wide = std::vec![data_request(LARGE_EXTENT_BITS); MAX_RESERVATION_BATCH + 1];
                assert_eq!(
                    allocator.reserve_backing(reservation, &wide),
                    Err(ReservationError::Batch {
                        requested: MAX_RESERVATION_BATCH + 1,
                        limit: MAX_RESERVATION_BATCH,
                    })
                );
                assert_eq!(allocator.reserved_extent_anchors(), 0);

                // The rolled-back records are ordinary capacity again.
                allocator
                    .reserve_backing(reservation, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                assert!(matches!(
                    allocator.reserve_backing(reservation, &[data_request(LARGE_EXTENT_BITS); 2]),
                    Err(ReservationError::Backing(
                        AllocError::UntypedExhausted { .. }
                    ))
                ));
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap().extents,
                    1
                );
                let arena = allocator.arena_owning_slots_for_test(0);
                assert!(
                    allocator
                        .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                        .is_ok()
                );
                assert_eq!(allocator.reserved_extent_anchors(), 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// The mapper consumes the lane the pricing resolved. Same window, same
    /// fresh aligned span, same 512-page request: the elastic lane takes the
    /// 2 MiB frame it was charged for, and the guaranteed lane takes base
    /// pages and one leaf table, so its promise does not depend on an aligned
    /// large-frame placement still being available.
    #[test]
    fn the_guaranteed_lane_maps_base_pages_where_the_elastic_lane_takes_a_large_frame() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::private_memory::Lane;
                for (lane, large, base, leaf_maps) in [
                    (Lane::LargeFrame, 1, 0, 0),
                    (Lane::BasePage, 0, MAX_PRIVATE_EXTENT_PAGES, 1),
                ] {
                    let (mut allocator, arena) =
                        setup_private_growth_fixture_for(MAX_PRIVATE_EXTENT_PAGES);
                    let mut region = Region::reserve(
                        &mut allocator,
                        0x1000_0000,
                        crate::private_memory::MAX_REGION_PAGES,
                        MAX_PRIVATE_EXTENT_PAGES,
                        false,
                    )
                    .expect("host test window");
                    let mut kernel = RecordingPrivateKernel::default();
                    let outcome = crate::private_memory::map_growth(
                        &mut allocator,
                        arena,
                        sel4::cap::VSpace::from_bits(7),
                        &mut region,
                        MAX_PRIVATE_EXTENT_PAGES,
                        crate::private_memory::GrowthPlan {
                            lane,
                            ..crate::private_memory::GrowthPlan::elastic()
                        },
                        &mut kernel,
                    )
                    .expect("host test growth");
                    assert_eq!(
                        (
                            outcome.large_frames,
                            outcome.base_frames,
                            outcome.pages_backed
                        ),
                        (large, base, MAX_PRIVATE_EXTENT_PAGES),
                        "lane {lane:?}"
                    );
                    assert_eq!(
                        kernel
                            .requests
                            .iter()
                            .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                            .count(),
                        leaf_maps,
                        "lane {lane:?}"
                    );
                    assert_eq!(
                        kernel
                            .requests
                            .iter()
                            .filter(|request| matches!(request, KernelRequest::MapFrame { .. }))
                            .count(),
                        large + base,
                        "lane {lane:?}"
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Borrowed backing is the arena's for every allocation purpose and the
    /// reservation's for every ownership purpose: it leaves the idle pool, it
    /// stays invisible to common capacity, its reservation cannot be closed
    /// while it is out, and the settle a completed revoke performs returns it
    /// to that same reservation rather than to the common pool.
    #[test]
    fn borrowed_backing_returns_to_its_own_reservation_and_never_to_common_capacity() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_backing(reservation, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                let extent = reserved_positions(&allocator)[0];

                let arena = allocator.arena_owning_slots_for_test(0);
                assert_eq!(
                    allocator.borrow_reserved(
                        reservation,
                        arena,
                        ReservedKind::Data,
                        LARGE_EXTENT_BITS
                    ),
                    Ok(extent)
                );
                // Selectable only through the source that certified it: a
                // pooled page may not be served from borrowed backing, and a
                // guaranteed page may not be served from anything else.
                assert_eq!(
                    allocator
                        .extent_for_allocation(
                            arena,
                            ExtentKind::PrivateData,
                            LARGE_EXTENT_BITS,
                            ExtentSource::Guaranteed(reservation),
                        )
                        .map(|(index, _)| index),
                    Ok(extent)
                );
                assert!(
                    allocator
                        .extent_for_allocation(
                            arena,
                            ExtentKind::PrivateData,
                            LARGE_EXTENT_BITS,
                            ExtentSource::Common,
                        )
                        .is_err()
                );
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap(),
                    ReservationBacking {
                        extents: 1,
                        bytes: MAX_PRIVATE_EXTENT_BYTES,
                        data_extents: 1,
                        table_extents: 0,
                        borrowed_extents: 1,
                        borrowed_bytes: MAX_PRIVATE_EXTENT_BYTES,
                    }
                );
                assert_eq!(
                    allocator
                        .reservation_backing(reservation)
                        .unwrap()
                        .available_extents(),
                    0
                );
                assert_eq!(allocator.borrowed_extent_bytes(), MAX_PRIVATE_EXTENT_BYTES);
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), 0);
                assert_eq!(allocator.reusable_extent_bytes(), 0);
                assert_eq!(allocator.elastic_inventory().bytes, 0);
                assert_eq!(
                    allocator.close_reservation(reservation),
                    Err(ReservationError::Occupied { extent })
                );
                assert_eq!(
                    allocator.borrow_reserved(
                        reservation,
                        arena,
                        ReservedKind::Data,
                        LARGE_EXTENT_BITS
                    ),
                    Err(ReservationError::Unavailable {
                        size_bits: LARGE_EXTENT_BITS
                    })
                );

                allocator.settle_returned_extent(extent);
                assert_eq!(allocator.reserved_extent_anchors(), 1);
                assert_eq!(allocator.borrowed_extent_bytes(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), 0);
                assert_eq!(allocator.elastic_inventory().bytes, 0);
                assert_eq!(
                    allocator
                        .reservation_backing(reservation)
                        .unwrap()
                        .available_extents(),
                    1
                );
                assert_eq!(allocator.close_reservation(reservation), Ok(1));
                assert_eq!(allocator.reusable_extent_anchors(), 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A guaranteed span is two aligned 2 MiB extents — one for payload, one
    /// for the leaf tables that payload's worst distribution needs — and a
    /// span request that cannot be completed returns every span it took,
    /// across batch boundaries.
    #[test]
    fn guarantee_spans_reserve_two_aligned_extents_each_and_roll_back_as_one() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    4,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 2).unwrap();
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap(),
                    ReservationBacking {
                        extents: 4,
                        bytes: 4 * MAX_PRIVATE_EXTENT_BYTES,
                        data_extents: 2,
                        table_extents: 2,
                        borrowed_extents: 0,
                        borrowed_bytes: 0,
                    }
                );
                assert_eq!(allocator.reusable_extent_anchors(), 0);

                // Nothing left: the refusal leaves the two spans already held.
                assert!(allocator.reserve_guarantee_spans(reservation, 1).is_err());
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap().extents,
                    4
                );
                assert_eq!(allocator.close_reservation(reservation), Ok(4));

                // A request wider than one batch that runs out in a later
                // batch returns every span, not just the failing batch's.
                let batch_spans = super::guarantee_vault::MAX_RESERVATION_BATCH / 2;
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2 * batch_spans - 2,
                );
                let anchors = allocator.reusable_extent_anchors();
                assert_eq!(anchors, 2 * batch_spans + 2);
                let wide = allocator.open_reservation().unwrap();
                assert!(
                    allocator
                        .reserve_guarantee_spans(wide, batch_spans + 2)
                        .is_err()
                );
                assert_eq!(allocator.reservation_backing(wide).unwrap().extents, 0);
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), anchors);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Guarantees are made physical simultaneously or not at all: an
    /// entitlement the machine cannot fund returns every entitlement reserved
    /// before it, so no graph is published against a partial promise.
    #[test]
    fn every_entitlement_guarantee_is_reserved_together_or_none_is() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::generation::reserve_guarantee_pages;
                let span_pages = super::guarantee_vault::GUARANTEE_SPAN_PAGES as u64;
                let mut allocator = reservation_fixture();
                // Two spans of capacity: enough for the first entitlement's
                // one span, not for both.
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    4,
                );
                assert!(
                    reserve_guarantee_pages(
                        &mut allocator,
                        &[(0, span_pages), (2, span_pages + 1)]
                    )
                    .is_err()
                );
                assert_eq!(allocator.reserved_extent_anchors(), 0);
                assert_eq!(allocator.live_reservations(), 0);
                assert_eq!(allocator.reusable_extent_anchors(), 4);

                // Both fit: each entitlement keeps its own identity, and the
                // totals are read back from what the allocator owns.
                let reservations =
                    reserve_guarantee_pages(&mut allocator, &[(0, span_pages), (2, span_pages)])
                        .expect("both guarantees fit");
                assert_eq!(reservations.len(), 2);
                assert_eq!(reservations.guarantee_pages, 2 * span_pages);
                assert_eq!(reservations.reserved_extents, 4);
                assert_eq!(reservations.reserved_bytes, 4 * MAX_PRIVATE_EXTENT_BYTES);
                // Four spent extent anchors, plus the withheld envelope: two
                // slots and two descriptors for every guaranteed page, being
                // that page's own frame and its worst-case leaf table.
                assert_eq!(reservations.reserved_slots, 4 + 2 * 2 * span_pages as usize);
                assert_eq!(
                    reservations.reserved_descriptors,
                    2 * 2 * span_pages as usize
                );
                assert_eq!(allocator.reserved_extent_anchors(), 4);
                assert_eq!(allocator.reusable_extent_anchors(), 0);
                assert_eq!(allocator.elastic_inventory().bytes, 0);
                let first = reservations.reservation_for(0).expect("first entitlement");
                let second = reservations.reservation_for(2).expect("second entitlement");
                assert_ne!(first.index(), second.index());
                assert_eq!(reservations.reservation_for(1), None);
                assert_eq!(allocator.reservation_backing(first).unwrap().extents, 2);

                // An entitlement promising nothing takes no identity.
                let mut none =
                    reserve_guarantee_pages(&mut allocator, &[(0, 0), (1, 0)]).expect("no promise");
                assert!(none.is_empty());
                assert_eq!(none.reserved_bytes, 0);
                assert_eq!(none.release(&mut allocator), Ok(()));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Descriptors and CSlots a reservation funds are withheld from every
    /// ordinary consumer for as long as it lives, and returned whole when it
    /// closes. Both are materialized before they are withheld, so the floor
    /// stands over storage that exists rather than over storage the metadata
    /// window might still fund.
    #[test]
    fn allocation_descriptor_threshold_matches_exact_available_count() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                let check = |allocator: &ObjectAllocator| {
                    let free = allocator.allocation_descriptors_free();
                    for requested in [0, 1, free.saturating_sub(1), free, free + 1, usize::MAX] {
                        assert_eq!(
                            allocator.has_allocation_descriptors(requested),
                            free >= requested,
                            "requested={requested}, free={free}"
                        );
                    }
                };
                check(&allocator);
                for remaining in [0, 1, 7, 31] {
                    allocator.reserve_stress_descriptors(remaining);
                    // Wherever the next record search begins, inside the
                    // occupied prefix or past it, the answer is the same.
                    for cursor in [
                        0,
                        allocator.allocations.len() / 2,
                        allocator.allocations.len() - 1,
                    ] {
                        allocator.allocation_search_start = cursor;
                        check(&allocator);
                    }
                    allocator.release_stress_descriptors();
                }
                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_guarantee_resources(reservation, 11, 0)
                    .unwrap();
                allocator
                    .reserve_operational_resources(
                        boot_contracts::private_memory_policy::ledger::Resources {
                            descriptors: 13,
                            ..boot_contracts::private_memory_policy::ledger::Resources::ZERO
                        },
                    )
                    .unwrap();
                check(&allocator);
                allocator.reserve_stress_descriptors(3);
                check(&allocator);
                allocator.operational_lent = true;
                check(&allocator);
                allocator.operational_lent = false;
                allocator.release_stress_descriptors();
                assert_eq!(allocator.close_reservation(reservation), Ok(0));
                check(&allocator);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn reserved_descriptors_and_slots_are_withheld_from_ordinary_consumers() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                let slots = allocator.free_slots();
                let descriptors = allocator.allocation_descriptors_free();
                let reservation = allocator.open_reservation().unwrap();
                // Everything but a small remainder, so an ordinary request
                // just past that remainder has to reach into the reservation
                // to be served — and must not be.
                let (held_descriptors, held_slots) = (descriptors - 8, slots - 8);
                assert_eq!(
                    allocator.reserve_guarantee_resources(
                        reservation,
                        held_descriptors,
                        held_slots
                    ),
                    Ok(())
                );
                assert_eq!(allocator.reserved_slots(), held_slots);
                assert_eq!(allocator.reserved_descriptors(), held_descriptors);
                assert_eq!(allocator.free_slots(), 8);
                assert_eq!(allocator.allocation_descriptors_free(), 8);
                // The elastic inventory reports the reduced figures, so a
                // policy is never admitted against capacity a guarantee owns.
                assert_eq!(allocator.elastic_inventory().slots, 8);

                let arena = allocator.arena_owning_slots_for_test(0);
                assert!(allocator.provision_private_slots(arena, 16).is_err());
                assert_eq!(allocator.reserved_slots(), held_slots);
                assert_eq!(allocator.free_slots(), 8);
                // What is left over is still ordinary capacity.
                assert_eq!(allocator.provision_private_slots(arena, 8), Ok(()));
                assert_eq!(allocator.free_slots(), 0);

                // Closing returns the withheld counts; the eight the arena
                // actually took stay taken, which is the difference between
                // withholding capacity and spending it.
                assert_eq!(allocator.close_reservation(reservation), Ok(0));
                assert_eq!(allocator.reserved_slots(), 0);
                assert_eq!(allocator.reserved_descriptors(), 0);
                assert_eq!(allocator.free_slots(), slots - 8);
                assert_eq!(allocator.allocation_descriptors_free(), descriptors - 8);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A guaranteed transaction is planned from the extents' own recorded
    /// bases and watermarks, borrows a further span only when the current one
    /// is full, refuses rather than reaching into the pool when the
    /// reservation is spent, and certifies against the ledger as protected
    /// backing.
    #[test]
    fn a_guaranteed_transaction_is_planned_from_recorded_extents_and_certified() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use boot_contracts::private_memory_policy::ledger;
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 1).unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);

                let acquired = allocator
                    .acquire_guaranteed(reservation, arena, 3, 1)
                    .expect("the reservation funds three pages and a table");
                assert_eq!(acquired.pages(), 3);
                assert_eq!(acquired.runs().len(), 2);
                assert_eq!(
                    acquired.resources(),
                    ledger::Resources {
                        bytes: 4 * GRANULE_BYTES as u64,
                        slots: 4,
                        descriptors: 4,
                        // The span's extents were charged when the
                        // reservation took them; a page inside one adds none.
                        extents: 0,
                        tables: 1,
                    }
                );
                // Every run starts at its extent's recorded base, and every
                // source is that extent, marked protected.
                for (run, source) in acquired.runs().iter().zip(acquired.sources()) {
                    assert_eq!(run.start, source.start);
                    assert_eq!(run.size_bits, GRANULE_EXTENT_BITS as u8);
                    assert_eq!(source.bytes, MAX_PRIVATE_EXTENT_BYTES as u64);
                    assert_eq!(source.class, ledger::Class::Guaranteed);
                }
                assert_eq!(acquired.runs()[0].count, 3);
                assert_eq!(acquired.runs()[1].count, 1);

                // The ledger certifies exactly this, and refuses the same
                // runs without the witness that authorizes them.
                assert!(
                    ledger::Plan::validate_runs(
                        acquired.sources(),
                        acquired.runs(),
                        acquired.resources(),
                        acquired.witness(),
                    )
                    .is_ok()
                );
                assert_eq!(
                    ledger::Plan::validate_runs(
                        acquired.sources(),
                        acquired.runs(),
                        acquired.resources(),
                        ledger::Witness {
                            guaranteed: ledger::Resources::ZERO,
                            guarantee_pages: 0,
                        },
                    ),
                    Err(ledger::Error::Guarantee)
                );

                // Both span extents are now borrowed, and the reservation has
                // nothing idle left.
                assert_eq!(
                    allocator
                        .reservation_backing(reservation)
                        .unwrap()
                        .available_extents(),
                    0
                );
                // A further request cannot be funded and is refused against
                // the reservation rather than served from the pool, even
                // though two 2 MiB extents are sitting in common capacity.
                assert_eq!(allocator.reusable_extent_anchors(), 0);
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                assert!(matches!(
                    allocator.acquire_guaranteed(
                        reservation,
                        arena,
                        MAX_PRIVATE_EXTENT_PAGES + 1,
                        0
                    ),
                    Err(ReservationError::Unavailable { .. })
                ));
                // The refusal returned everything it had borrowed for that
                // attempt: the pool's spare extent is untouched.
                assert_eq!(allocator.reusable_extent_anchors(), 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// The shape a real adaptive holder's first growth takes: a whole
    /// entitlement redeemed at once, spanning several borrowed extents, with
    /// one leaf table per address span. Every run must certify against its
    /// own protected source and the totals must reconcile exactly.
    #[test]
    fn a_whole_entitlement_redeemed_at_once_certifies_run_by_run() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use boot_contracts::private_memory_policy::ledger;
                const PAGES: usize = 4 * MAX_PRIVATE_EXTENT_PAGES;
                const TABLES: usize = 4;
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    8,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 4).unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);

                let acquired = allocator
                    .acquire_guaranteed(reservation, arena, PAGES, TABLES)
                    .expect("four spans fund four spans of pages");
                assert_eq!(acquired.pages(), PAGES);
                assert_eq!(acquired.runs().len(), 5);
                let placed: u64 = acquired
                    .runs()
                    .iter()
                    .map(|run| run.count * (1u64 << run.size_bits))
                    .sum();
                assert_eq!(placed, acquired.resources().bytes);
                // Every run sits inside the protected source recorded beside
                // it, and no two runs overlap.
                for (run, source) in acquired.runs().iter().zip(acquired.sources()) {
                    let end = run.start + run.count * (1u64 << run.size_bits);
                    assert!(run.start >= source.start, "run {run:?} source {source:?}");
                    assert!(
                        end <= source.start + source.bytes,
                        "run {run:?} source {source:?}"
                    );
                }
                assert_eq!(
                    ledger::Plan::validate_runs(
                        acquired.sources(),
                        acquired.runs(),
                        acquired.resources(),
                        acquired.witness(),
                    )
                    .map(|plan| plan.guarantee_pages()),
                    Ok(PAGES as u64)
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A guaranteed growth needs its own descriptors and CSlots, and they
    /// come from the entitlement's withheld funding rather than from the
    /// pool. Without that lend the mapping fails with nothing placed, which
    /// is the defect this covers: the pooled half provisions descriptors for
    /// its own objects only, so a wholly guaranteed growth provisioned none.
    #[test]
    fn a_guaranteed_growth_is_funded_by_its_entitlement_not_by_the_pool() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                const PAGES: usize = 4;
                const TABLES: usize = 1;
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 1).unwrap();
                allocator
                    .reserve_guarantee_resources(reservation, PAGES + TABLES, PAGES + TABLES)
                    .unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(arena).unwrap();
                let acquired = allocator
                    .acquire_guaranteed(reservation, arena, PAGES, TABLES)
                    .expect("the reservation funds the backing");
                assert_eq!(acquired.pages() + acquired.tables(), PAGES + TABLES);

                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    crate::private_memory::MAX_REGION_PAGES,
                    true,
                )
                .expect("host test window");
                let plan = crate::private_memory::GrowthPlan {
                    lane: crate::private_memory::Lane::BasePage,
                    guaranteed_pages: PAGES,
                    reservation: Some(reservation),
                };
                let mut kernel = RecordingPrivateKernel::default();

                // Backing alone is not enough: with no descriptor records the
                // growth cannot place its first page.
                assert!(
                    crate::private_memory::map_growth(
                        &mut allocator,
                        arena,
                        sel4::cap::VSpace::from_bits(7),
                        &mut region,
                        PAGES,
                        plan,
                        &mut kernel,
                    )
                    .is_err()
                );
                assert_eq!(region.pages(), 0);

                // Lending the entitlement's own withheld funding is what makes
                // the same growth payable.
                let lent = PAGES + TABLES;
                allocator
                    .lend_reserved_resources(reservation, lent, lent)
                    .unwrap();
                allocator.provision_private_slots(arena, lent).unwrap();
                let mut kernel = RecordingPrivateKernel::default();
                let outcome = crate::private_memory::map_growth(
                    &mut allocator,
                    arena,
                    sel4::cap::VSpace::from_bits(7),
                    &mut region,
                    PAGES,
                    plan,
                    &mut kernel,
                )
                .expect("funded guaranteed growth");
                assert_eq!(
                    (
                        outcome.large_frames,
                        outcome.base_frames,
                        outcome.pages_backed
                    ),
                    (0, PAGES, PAGES)
                );
                assert_eq!(
                    kernel
                        .requests
                        .iter()
                        .filter(|request| matches!(request, KernelRequest::MapLeaf { .. }))
                        .count(),
                    TABLES
                );
                // Every object came from the reservation's borrowed backing,
                // so the entitlement's idle capacity is what shrank.
                assert_eq!(
                    allocator
                        .reservation_backing(reservation)
                        .unwrap()
                        .borrowed_extents,
                    2
                );
                assert_eq!(allocator.reserved_descriptors(), 0);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Funding an incarnation drew from its entitlement comes back when it
    /// retires, so a replacement can be funded. Without the restore the floor
    /// shrinks once per incarnation and the second one is refused against a
    /// reservation that still owns all of its backing.
    #[test]
    fn retiring_an_incarnation_returns_the_funding_it_drew_from_its_entitlement() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                let reservation = allocator.open_reservation().unwrap();
                allocator
                    .reserve_guarantee_resources(reservation, 16, 16)
                    .unwrap();
                assert_eq!(allocator.reserved_descriptors(), 16);

                // One incarnation spends most of the floor.
                allocator
                    .lend_reserved_resources(reservation, 12, 12)
                    .unwrap();
                assert_eq!(allocator.reserved_descriptors(), 4);
                assert_eq!(allocator.reserved_slots(), 4);
                // A second incarnation of the same size cannot be funded
                // while the first still holds it.
                assert!(matches!(
                    allocator.lend_reserved_resources(reservation, 12, 12),
                    Err(ReservationError::Unavailable { .. })
                ));

                // Retirement returns exactly what was drawn.
                allocator.restore_reserved_resources(reservation, 12, 12);
                assert_eq!(allocator.reserved_descriptors(), 16);
                assert_eq!(allocator.reserved_slots(), 16);
                assert_eq!(
                    allocator.lend_reserved_resources(reservation, 12, 12),
                    Ok(())
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A borrow names one reservation, one kind and one size. Nothing else may
    /// be served from it, and a stale identity borrows nothing at all.
    #[test]
    fn a_borrow_matches_its_reservation_kind_and_size_exactly() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                let first = allocator.open_reservation().unwrap();
                let second = allocator.open_reservation().unwrap();
                allocator
                    .reserve_backing(first, &[data_request(LARGE_EXTENT_BITS)])
                    .unwrap();
                allocator
                    .reserve_backing(second, &[data_request(GRANULE_EXTENT_BITS)])
                    .unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);

                assert_eq!(
                    allocator.borrow_reserved(
                        first,
                        arena,
                        ReservedKind::Data,
                        GRANULE_EXTENT_BITS
                    ),
                    Err(ReservationError::Unavailable {
                        size_bits: GRANULE_EXTENT_BITS
                    })
                );
                assert_eq!(
                    allocator.borrow_reserved(
                        second,
                        arena,
                        ReservedKind::Tables,
                        GRANULE_EXTENT_BITS
                    ),
                    Err(ReservationError::Unavailable {
                        size_bits: GRANULE_EXTENT_BITS
                    })
                );
                assert_eq!(allocator.borrowed_extent_bytes(), 0);

                let stale = first;
                let borrowed = allocator
                    .borrow_reserved(first, arena, ReservedKind::Data, LARGE_EXTENT_BITS)
                    .unwrap();
                allocator.settle_returned_extent(borrowed);
                assert_eq!(allocator.close_reservation(first), Ok(1));
                assert_eq!(
                    allocator.borrow_reserved(stale, arena, ReservedKind::Data, LARGE_EXTENT_BITS),
                    Err(ReservationError::UnknownReservation(stale))
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// One-entitlement policy whose single subject may redeem `guarantee`
    /// pages and grow into the pool beyond them.
    fn guaranteed_policy(guarantee: u64) -> Vec<u8> {
        use boot_contracts::private_memory_policy::{self as policy, Entitlement, Header, Subject};
        let entitlement = Entitlement {
            identity: policy::entitlement_identity("guaranteed"),
            subtree_root: [0; 32],
            guarantee_pages: guarantee,
            maximum_pages: 0,
            maximum_mode: policy::POOL,
            reserved: 0,
        };
        let subject = Subject {
            identity: policy::subject_identity("holder"),
            entitlement: entitlement.identity,
            maximum_pages: 0,
            maximum_mode: policy::POOL,
            reserved: 0,
        };
        let header = Header {
            magic: policy::MAGIC,
            format_version: policy::FORMAT_VERSION,
            header_size: policy::HEADER_BYTES as u32,
            required_flags: 0,
            entitlement_count: 1,
            subject_count: 1,
            total_len: (policy::HEADER_BYTES + policy::ENTITLEMENT_BYTES + policy::SUBJECT_BYTES)
                as u32,
            reserved: 0,
            reserve_bytes: 0,
            reserve_slots: 0,
            reserve_descriptors: 0,
            reserve_extents: 0,
            reserve_tables: 0,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend(entitlement.encode());
        bytes.extend(subject.encode());
        bytes
    }

    fn guaranteed_ledger(
        policy: &[u8],
        guarantee: u64,
    ) -> (
        boot_contracts::private_memory_policy::ledger::Ledger<'_>,
        boot_contracts::private_memory_policy::ledger::Incarnation,
    ) {
        use boot_contracts::private_memory_policy::{self as policy, Instance, ledger};
        let decoded = policy::Policy::decode(policy).unwrap();
        let instances = [Instance {
            identity: policy::subject_identity("holder"),
            owner: None,
        }];
        let envelope = ledger::Resources {
            bytes: 2 * guarantee * policy::PAGE_BYTES,
            slots: 2 * guarantee,
            descriptors: 2 * guarantee,
            extents: if guarantee == 0 { 0 } else { 2 },
            tables: guarantee,
        };
        let available = ledger::Resources {
            bytes: 1 << 30,
            slots: 1 << 20,
            descriptors: 1 << 20,
            extents: 1 << 16,
            tables: 1 << 16,
        }
        .checked_add(envelope)
        .unwrap();
        let mut ledger =
            ledger::Ledger::admit(decoded, &instances, available, &[envelope]).unwrap();
        let token = ledger.bind(&policy::subject_identity("holder")).unwrap();
        (ledger, token)
    }

    /// A guarantee that ends exactly at a span boundary funds that span's
    /// table only; the next span's table is pooled, like the page it maps.
    /// Charging every table to the guarantee left the pooled page asking the
    /// pool for a table no source had acquired, and the growth failed after
    /// mapping the whole guarantee.
    #[test]
    fn a_guarantee_ending_at_a_span_boundary_leaves_the_next_table_pooled() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                const GUARANTEE: usize = MAX_PRIVATE_EXTENT_PAGES;
                let mut allocator = reservation_fixture();
                // Pooled backing for one page and one table, and nothing more:
                // a pooled half priced with no table would still fail to map.
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateTables,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 1).unwrap();
                allocator
                    .reserve_guarantee_resources(reservation, GUARANTEE + 1, GUARANTEE + 1)
                    .unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(arena).unwrap();
                let policy = guaranteed_policy(GUARANTEE as u64);
                let (mut ledger, token) = guaranteed_ledger(&policy, GUARANTEE as u64);
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    crate::private_memory::MAX_REGION_PAGES,
                    true,
                )
                .expect("host test window");
                let (_, prefix_tables) = region.shape_split(
                    GUARANTEE + 1,
                    crate::private_memory::Lane::BasePage,
                    GUARANTEE,
                );
                assert_eq!(prefix_tables, 1);

                let mut table = Table::new();
                let mut kernel = RecordingPrivateKernel::default();
                let previous = crate::private_memory::elastic::grow(
                    &mut table,
                    &mut allocator,
                    &mut ledger,
                    token,
                    arena,
                    sel4::cap::VSpace::from_bits(7),
                    &mut region,
                    GUARANTEE + 1,
                    crate::private_memory::GrowthPlan {
                        lane: crate::private_memory::Lane::BasePage,
                        guaranteed_pages: GUARANTEE,
                        reservation: Some(reservation),
                    },
                    &mut kernel,
                )
                .expect("the guarantee and one pooled page and table are all present");
                assert_eq!(previous, 0);
                assert_eq!((region.pages(), region.leaf_tables()), (GUARANTEE + 1, 2));
                assert_eq!(ledger.pages(token), Ok(GUARANTEE as u64 + 1));
                // Exactly one table was charged to the guarantee.
                assert_eq!(ledger.guaranteed_held(token).unwrap().tables, 1);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A guaranteed growth that fails after the ledger opened its transaction
    /// hands back every descriptor and CSlot it borrowed from its
    /// entitlement. The abort charged the entitlement nothing and retirement
    /// restores only what a commit charged, so a lend kept here would be gone
    /// for good, and after a few failures no guaranteed page could be funded.
    #[test]
    fn a_failed_guaranteed_growth_returns_its_lent_funding() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                const PAGES: usize = 4;
                const FUNDING: usize = PAGES + 1;
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    2,
                );
                let reservation = allocator.open_reservation().unwrap();
                allocator.reserve_guarantee_spans(reservation, 1).unwrap();
                allocator
                    .reserve_guarantee_resources(reservation, FUNDING, FUNDING)
                    .unwrap();
                let arena = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(arena).unwrap();
                let policy = guaranteed_policy(PAGES as u64);
                let (mut ledger, token) = guaranteed_ledger(&policy, PAGES as u64);
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    crate::private_memory::MAX_REGION_PAGES,
                    true,
                )
                .expect("host test window");
                let plan = crate::private_memory::GrowthPlan {
                    lane: crate::private_memory::Lane::BasePage,
                    guaranteed_pages: PAGES,
                    reservation: Some(reservation),
                };
                let floor = (allocator.reserved_descriptors(), allocator.reserved_slots());
                let backing = allocator.reservation_backing(reservation).unwrap();
                let mut table = Table::new();

                // Every attempt fails on its second frame, after the ledger
                // began. More attempts than the funding could survive once.
                for _ in 0..3 * FUNDING {
                    let mut kernel = RecordingPrivateKernel {
                        fail_map_frame_at: Some(2),
                        ..RecordingPrivateKernel::default()
                    };
                    assert!(matches!(
                        crate::private_memory::elastic::grow(
                            &mut table,
                            &mut allocator,
                            &mut ledger,
                            token,
                            arena,
                            sel4::cap::VSpace::from_bits(7),
                            &mut region,
                            PAGES,
                            plan,
                            &mut kernel,
                        ),
                        Err(crate::private_memory::elastic::ElasticGrowError::Frames {
                            allocated: 1,
                            ..
                        })
                    ));
                    assert_eq!(region.pages(), 0);
                    assert_eq!(
                        (allocator.reserved_descriptors(), allocator.reserved_slots()),
                        floor
                    );
                    assert_eq!(ledger.redeemable_guarantee(token), Ok(PAGES as u64));
                }

                // The guarantee is still whole and still fundable.
                let mut kernel = RecordingPrivateKernel::default();
                crate::private_memory::elastic::grow(
                    &mut table,
                    &mut allocator,
                    &mut ledger,
                    token,
                    arena,
                    sel4::cap::VSpace::from_bits(7),
                    &mut region,
                    PAGES,
                    plan,
                    &mut kernel,
                )
                .expect("the guarantee survives its failed attempts");
                assert_eq!(region.pages(), PAGES);
                assert_eq!(ledger.redeemable_guarantee(token), Ok(0));
                assert_eq!(
                    allocator.reservation_backing(reservation).unwrap().extents,
                    backing.extents
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Serving one growth request reads the same records however much the
    /// holder already has.
    ///
    /// Each request's returned extents are seeded just before it, as the
    /// matrix's small schedule finds them after its bulk schedule, so both
    /// tables gain present records between the compared requests: a walk of
    /// the extent table would read at least the 10 extent records gained, and
    /// a walk of the allocation table at least the 512 allocation records.
    #[test]
    fn a_growth_request_reads_no_more_records_when_the_holder_holds_twice_the_pages() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                // Records a request may read beyond the one before it for
                // steps that do not depend on what the holder holds. Smaller
                // than either table's growth between the compared requests,
                // so no walk of either table fits inside it.
                const ALLOWANCE: usize = 8;
                const REQUEST: usize = 511;
                let mut allocator = reservation_fixture();
                let arena = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(arena).unwrap();
                let policy = guaranteed_policy(0);
                let (mut ledger, token) = guaranteed_ledger(&policy, 0);
                let mut region = Region::reserve(
                    &mut allocator,
                    0x1000_0000,
                    crate::private_memory::MAX_REGION_PAGES,
                    crate::private_memory::MAX_REGION_PAGES,
                    true,
                )
                .expect("host test window");
                assert!(region.reservation() >= 4 * REQUEST);
                let mut table = Table::new();
                let mut kernel = RecordingPrivateKernel::default();
                let mut reads = [0; 4];
                let mut held = [(0, 0); 4];
                for (request, read) in reads.iter_mut().enumerate() {
                    let (shape, _) =
                        region.shape_split(REQUEST, crate::private_memory::Lane::BasePage, 0);
                    assert_eq!((shape.large_frames, shape.base_pages), (0, REQUEST));
                    for bits in (GRANULE_EXTENT_BITS..LARGE_EXTENT_BITS).rev() {
                        if shape.base_pages & (1 << (bits - GRANULE_EXTENT_BITS)) != 0 {
                            seed_reusable_extents(&mut allocator, ExtentKind::PrivateData, bits, 1);
                        }
                    }
                    seed_reusable_extents(
                        &mut allocator,
                        ExtentKind::PrivateTables,
                        GRANULE_EXTENT_BITS,
                        shape.tables,
                    );
                    held[request] = (
                        allocator.extents.iter().flatten().count(),
                        allocator
                            .allocations
                            .iter()
                            .filter(|record| record.owner != u16::MAX)
                            .count(),
                    );
                    allocator.reset_record_reads();
                    let previous = crate::private_memory::elastic::grow(
                        &mut table,
                        &mut allocator,
                        &mut ledger,
                        token,
                        arena,
                        sel4::cap::VSpace::from_bits(7),
                        &mut region,
                        REQUEST,
                        crate::private_memory::GrowthPlan {
                            lane: crate::private_memory::Lane::BasePage,
                            guaranteed_pages: 0,
                            reservation: None,
                        },
                        &mut kernel,
                    )
                    .expect("every extent the request needs was returned before it");
                    *read = allocator.record_reads();
                    assert_eq!(previous, request * REQUEST);
                }
                assert!(
                    held[2].0 > held[1].0 && held[2].1 > held[1].1,
                    "both tables gained records between the compared requests: {held:?}"
                );
                assert!(
                    reads[2] <= reads[1] + ALLOWANCE,
                    "records read per request at 0, 511, 1022 and 1533 pages held: {reads:?}"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Best fit by extent size on an elastic arena and first fit by index on a
    /// fixed one, pinned before the selection structure changes. Best fit is
    /// what keeps a base page off the aligned extent a large frame in the same
    /// transaction was planned to occupy.
    #[test]
    fn an_elastic_arena_takes_the_smallest_extent_with_room_and_a_fixed_arena_the_first() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(&mut allocator, ExtentKind::PrivateData, 13, 2);
                let arena = allocator.arena_owning_slots_for_test(0);
                let large = allocator
                    .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                let small = allocator
                    .provision_extent(arena, 13, ExtentKind::PrivateData)
                    .unwrap();
                let other = allocator
                    .provision_extent(arena, 13, ExtentKind::PrivateData)
                    .unwrap();
                assert!(large < small && small < other);
                let select = |allocator: &ObjectAllocator, size_bits| {
                    allocator
                        .extent_for_allocation(
                            arena,
                            ExtentKind::PrivateData,
                            size_bits,
                            ExtentSource::Common,
                        )
                        .map(|(index, _)| index)
                };
                let too_small = |size_bits: usize| AllocError::ArenaTooSmall {
                    size_bits,
                    required: 1 << size_bits,
                };

                // Fixed: the lowest index with room, whatever its size.
                assert_eq!(select(&allocator, GRANULE_EXTENT_BITS), Ok(large));
                assert_eq!(select(&allocator, LARGE_EXTENT_BITS), Ok(large));

                // Elastic: the smallest extent with room, the lower index
                // first among equals; a 2 MiB frame still takes the 2 MiB one.
                allocator.mark_arena_elastic(arena).unwrap();
                assert_eq!(select(&allocator, GRANULE_EXTENT_BITS), Ok(small));
                assert_eq!(select(&allocator, LARGE_EXTENT_BITS), Ok(large));

                // One granule in the 2 MiB extent leaves it no room for a
                // frame, and a granule still goes to the smallest extent.
                allocator
                    .extents
                    .update(large, |extent| extent.watermark = GRANULE_BYTES);
                assert_eq!(
                    select(&allocator, LARGE_EXTENT_BITS),
                    Err(too_small(LARGE_EXTENT_BITS))
                );
                assert_eq!(select(&allocator, GRANULE_EXTENT_BITS), Ok(small));

                // A second, untouched 2 MiB extent takes the frame.
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                let second = allocator
                    .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                assert_eq!(select(&allocator, LARGE_EXTENT_BITS), Ok(second));
                assert_eq!(select(&allocator, GRANULE_EXTENT_BITS), Ok(small));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// The selection rule follows the arena's mode at the moment of each
    /// selection: a page taken first fit is followed, once the arena is
    /// marked elastic, by one taken best fit.
    #[test]
    fn marking_an_arena_elastic_switches_its_next_selection_to_best_fit() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    LARGE_EXTENT_BITS,
                    1,
                );
                seed_reusable_extents(&mut allocator, ExtentKind::PrivateData, 13, 1);
                let arena = allocator.arena_owning_slots_for_test(0);
                let large = allocator
                    .provision_extent(arena, LARGE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                let small = allocator
                    .provision_extent(arena, 13, ExtentKind::PrivateData)
                    .unwrap();
                allocator.provision_private_slots(arena, 2).unwrap();
                let mut kernel = RecordingPrivateKernel::default();
                let mut granule = |allocator: &mut ObjectAllocator| {
                    let allocation = allocator
                        .acquire_private_in(
                            arena,
                            PrivateObjectKind::Granule,
                            sel4::cap_type::Granule::object_blueprint(),
                            ExtentSource::Common,
                            &mut kernel,
                        )
                        .unwrap();
                    allocator.allocations[allocation.position as usize].extent as usize
                };
                assert_eq!(granule(&mut allocator), large);
                allocator.mark_arena_elastic(arena).unwrap();
                assert_eq!(granule(&mut allocator), small);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A request no extent of the arena has room for is refused by name, and
    /// before any record is taken or the kernel is asked.
    #[test]
    fn a_request_no_extent_has_room_for_is_refused_as_arena_too_small() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                let arena = allocator.arena_owning_slots_for_test(0);
                allocator.mark_arena_elastic(arena).unwrap();
                let data = allocator
                    .provision_extent(arena, GRANULE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                let reservation = allocator.open_reservation().unwrap();
                let too_small = |size_bits: usize| {
                    Err(AllocError::ArenaTooSmall {
                        size_bits,
                        required: 1 << size_bits,
                    })
                };
                let select = |allocator: &ObjectAllocator, kind, size_bits, source| {
                    allocator.extent_for_allocation(arena, kind, size_bits, source)
                };
                let common = ExtentSource::Common;

                // Too large for the only extent, of a kind it is not, and
                // from a source it is not.
                assert_eq!(
                    select(
                        &allocator,
                        ExtentKind::PrivateData,
                        LARGE_EXTENT_BITS,
                        common
                    ),
                    too_small(LARGE_EXTENT_BITS)
                );
                assert_eq!(
                    select(
                        &allocator,
                        ExtentKind::PrivateTables,
                        GRANULE_EXTENT_BITS,
                        common
                    ),
                    too_small(GRANULE_EXTENT_BITS)
                );
                assert_eq!(
                    select(
                        &allocator,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        ExtentSource::Guaranteed(reservation)
                    ),
                    too_small(GRANULE_EXTENT_BITS)
                );
                assert_eq!(
                    select(
                        &allocator,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        common
                    )
                    .map(|(index, _)| index),
                    Ok(data)
                );

                // Full: nothing has room, through selection and acquisition.
                allocator
                    .extents
                    .update(data, |extent| extent.watermark = GRANULE_BYTES);
                assert_eq!(
                    select(
                        &allocator,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        common
                    ),
                    too_small(GRANULE_EXTENT_BITS)
                );
                allocator.provision_private_slots(arena, 1).unwrap();
                let free = allocator.allocation_descriptors_free();
                let mut kernel = RecordingPrivateKernel::default();
                let refused = allocator
                    .acquire_private_in(
                        arena,
                        PrivateObjectKind::Granule,
                        sel4::cap_type::Granule::object_blueprint(),
                        common,
                        &mut kernel,
                    )
                    .map(|_| ());
                assert_eq!(
                    refused,
                    too_small(GRANULE_EXTENT_BITS).map(|_: (usize, usize)| ())
                );
                assert!(kernel.requests.is_empty());
                assert_eq!(allocator.allocation_descriptors_free(), free);
                assert_eq!(allocator.extents[data].unwrap().watermark, GRANULE_BYTES);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A page the arena has no spare record for is refused by name after its
    /// extent was chosen and before anything is retyped or mapped: the extent
    /// keeps its room and the descriptor pool its records.
    #[test]
    fn a_page_with_no_spare_record_is_refused_before_it_is_retyped_or_mapped() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                seed_reusable_extents(
                    &mut allocator,
                    ExtentKind::PrivateData,
                    GRANULE_EXTENT_BITS,
                    1,
                );
                // One CSlot owned, so the arena's chains are walked, and no
                // record on any of them.
                let arena = allocator.arena_owning_slots_for_test(1);
                let data = allocator
                    .provision_extent(arena, GRANULE_EXTENT_BITS, ExtentKind::PrivateData)
                    .unwrap();
                let free = allocator.allocation_descriptors_free();
                let mut kernel = RecordingPrivateKernel::default();
                let refused = allocator
                    .acquire_private_in(
                        arena,
                        PrivateObjectKind::Granule,
                        sel4::cap_type::Granule::object_blueprint(),
                        ExtentSource::Common,
                        &mut kernel,
                    )
                    .map(|_| ());
                assert_eq!(
                    refused,
                    Err(AllocError::ArenaSlotTableFull {
                        limit: MAX_TASK_ALLOCATIONS,
                    })
                );
                assert!(kernel.requests.is_empty());
                assert_eq!(allocator.extents[data].unwrap().watermark, 0);
                assert_eq!(allocator.allocation_descriptors_free(), free);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A growth whose descriptor page the metadata window cannot fund is
    /// refused while it provisions descriptors, which precedes every mapping,
    /// and takes no CSlot or record. On the host the window is closed by
    /// construction; the refusal carries the name it has today.
    #[test]
    fn a_growth_whose_descriptor_page_cannot_be_funded_is_refused_before_any_page_is_mapped() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = reservation_fixture();
                let arena = allocator.arena_owning_slots_for_test(0);
                assert!(allocator.reserve_stress_descriptors(0) > 0);
                assert_eq!(allocator.allocation_descriptors_free(), 0);
                let slots = allocator.free_slots();
                assert_eq!(
                    allocator.provision_private_slots(arena, 1),
                    Err(AllocError::NoKernelUntyped)
                );
                assert_eq!(allocator.free_slots(), slots);
                assert_eq!(allocator.arena_slot_count(arena), Ok(0));
                assert_eq!(allocator.allocation_descriptors_free(), 0);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// An elastic arena holding one 4 KiB data extent with room, a 4 KiB
    /// table extent and one spare record, for the recount and chain tests.
    fn room_chain_fixture() -> (ObjectAllocator, TaskArenaId, usize, usize) {
        let mut allocator = reservation_fixture();
        seed_reusable_extents(
            &mut allocator,
            ExtentKind::PrivateData,
            GRANULE_EXTENT_BITS,
            1,
        );
        seed_reusable_extents(
            &mut allocator,
            ExtentKind::PrivateTables,
            GRANULE_EXTENT_BITS,
            1,
        );
        let arena = allocator.arena_owning_slots_for_test(0);
        allocator.mark_arena_elastic(arena).unwrap();
        let data = allocator
            .provision_extent(arena, GRANULE_EXTENT_BITS, ExtentKind::PrivateData)
            .unwrap();
        let tables = allocator
            .provision_extent(arena, GRANULE_EXTENT_BITS, ExtentKind::PrivateTables)
            .unwrap();
        allocator.provision_private_slots(arena, 1).unwrap();
        (allocator, arena, data, tables)
    }

    /// The panic message of one fixture's thread, or `None` when it ran clean.
    fn room_chain_panic(
        case: impl FnOnce(&mut ObjectAllocator, TaskArenaId, usize, usize) + Send + 'static,
    ) -> Option<std::string::String> {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(move || {
                let (mut allocator, arena, data, tables) = room_chain_fixture();
                case(&mut allocator, arena, data, tables);
            })
            .unwrap()
            .join()
            .err()
            .map(|payload| {
                payload
                    .downcast_ref::<std::string::String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).into()))
                    .unwrap_or_default()
            })
    }

    /// Every figure the allocator maintains instead of counting is compared
    /// with a full recount wherever a host test reads it, so no test needs to
    /// know which figure it exercises: one made to disagree with its records
    /// fails at its next read, and the same read of an undisturbed figure
    /// passes.
    #[test]
    fn a_maintained_count_that_drifts_from_its_recount_fails_the_next_read() {
        use super::record_tables::ExtentDrift;
        type Drift = fn(&mut ObjectAllocator, TaskArenaId);
        type Read = fn(&mut ObjectAllocator, TaskArenaId);
        let cases: [(&str, Drift, Read); 7] = [
            (
                "owned allocation records",
                |allocator, _| allocator.allocations.drift_for_test(),
                |allocator, _| {
                    allocator.allocation_descriptors_free();
                },
            ),
            (
                "present extent records",
                |allocator, _| allocator.extents.drift_for_test(ExtentDrift::Present),
                |allocator, _| {
                    allocator.extent_descriptors_free();
                },
            ),
            (
                "reusable extent bytes",
                |allocator, _| allocator.extents.drift_for_test(ExtentDrift::FreeBytes),
                |allocator, _| {
                    allocator.reusable_extent_bytes();
                },
            ),
            (
                "returned extents of one size",
                |allocator, _| {
                    allocator
                        .extents
                        .drift_for_test(ExtentDrift::Reuse { size_bits: 13 })
                },
                |allocator, _| {
                    allocator.reusable_extent(13);
                },
            ),
            (
                "the cursor to the lowest returned extent of one size",
                |allocator, _| {
                    seed_reusable_extents(allocator, ExtentKind::PrivateData, 13, 1);
                    allocator
                        .extents
                        .drift_for_test(ExtentDrift::ReuseCursor { size_bits: 13 })
                },
                |allocator, _| {
                    allocator.reusable_extent(13);
                },
            ),
            (
                "the cursor to the lowest vacant extent slot",
                |allocator, _| allocator.extents.drift_for_test(ExtentDrift::Vacancy),
                |allocator, _| {
                    // No returned extent of this size, so a fresh record is
                    // placed; the host has no untyped to retype it from.
                    let _ = allocator.acquire_extent_record(14);
                },
            ),
            (
                "the room chain",
                |allocator, arena| {
                    allocator.extents.drift_for_test(ExtentDrift::RoomChain {
                        arena: arena.index(),
                    })
                },
                |allocator, arena| {
                    let _ = allocator.extent_for_allocation(
                        arena,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        ExtentSource::Common,
                    );
                },
            ),
        ];
        for (figure, drift, read) in cases {
            let drifted = room_chain_panic(move |allocator, arena, _, _| {
                drift(allocator, arena);
                read(allocator, arena);
            });
            assert!(
                drifted
                    .as_deref()
                    .is_some_and(|message| message.contains("recount")),
                "{figure}: a drifted figure must fail its next read, got {drifted:?}"
            );
            let clean = room_chain_panic(move |allocator, arena, _, _| read(allocator, arena));
            assert_eq!(
                clean, None,
                "{figure}: an undisturbed figure must pass its read"
            );
        }
    }

    /// A room chain that names anything but the arena's extents with room, in
    /// order, refuses the request by name: nothing is taken from what the bad
    /// link names, nothing reaches the kernel, and the walk ends.
    #[test]
    fn a_room_chain_link_that_names_no_extent_with_room_is_refused_by_name() {
        type Corrupt = fn(&mut ObjectAllocator, TaskArenaId, usize, usize);
        let broken = Err(AllocError::ArenaTableFull {
            limit: MAX_TASK_EXTENTS,
        });
        let cases: [(&str, PrivateObjectKind, Corrupt); 5] = [
            (
                "a vacant slot",
                PrivateObjectKind::Granule,
                |allocator, arena, _, _| {
                    let vacant = allocator.extents.iter().position(Option::is_none).unwrap();
                    allocator
                        .extents
                        .set_room_head_for_test(arena.index(), vacant as u32);
                },
            ),
            (
                "a full extent",
                PrivateObjectKind::Granule,
                |allocator, arena, _, _| {
                    seed_reusable_extents(
                        allocator,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        1,
                    );
                    let full = allocator
                        .provision_extent(arena, GRANULE_EXTENT_BITS, ExtentKind::PrivateData)
                        .unwrap();
                    allocator
                        .extents
                        .update(full, |extent| extent.watermark = GRANULE_BYTES);
                    allocator
                        .extents
                        .set_room_head_for_test(arena.index(), full as u32);
                },
            ),
            (
                "another arena's extent",
                PrivateObjectKind::Granule,
                |allocator, arena, _, _| {
                    seed_reusable_extents(
                        allocator,
                        ExtentKind::PrivateData,
                        GRANULE_EXTENT_BITS,
                        1,
                    );
                    let other = allocator.arena_owning_slots_for_test(0);
                    let foreign = allocator
                        .provision_extent(other, GRANULE_EXTENT_BITS, ExtentKind::PrivateData)
                        .unwrap();
                    allocator
                        .extents
                        .set_room_head_for_test(arena.index(), foreign as u32);
                },
            ),
            (
                "an extent out of order",
                PrivateObjectKind::LeafTable,
                |allocator, arena, data, _| {
                    // A larger data extent linked ahead of a smaller one:
                    // a table request passes both, so the order is checked
                    // before anything fits.
                    seed_reusable_extents(allocator, ExtentKind::PrivateData, 13, 1);
                    let larger = allocator
                        .provision_extent(arena, 13, ExtentKind::PrivateData)
                        .unwrap();
                    allocator
                        .extents
                        .set_room_head_for_test(arena.index(), larger as u32);
                    allocator
                        .extents
                        .set_room_link_for_test(larger, data as u32);
                },
            ),
            (
                "an extent linked to itself",
                PrivateObjectKind::LeafTable,
                |allocator, _, data, _| {
                    allocator.extents.set_room_link_for_test(data, data as u32);
                },
            ),
        ];
        for (link, kind, corrupt) in cases {
            let failed = room_chain_panic(move |allocator, arena, data, tables| {
                corrupt(allocator, arena, data, tables);
                let blueprint = match kind {
                    PrivateObjectKind::LeafTable => {
                        crate::child_vspace::private_leaf_table_type().blueprint()
                    }
                    _ => sel4::cap_type::Granule::object_blueprint(),
                };
                let free = allocator.allocation_descriptors_free();
                let mut kernel = RecordingPrivateKernel::default();
                let refused = allocator
                    .acquire_private_in(arena, kind, blueprint, ExtentSource::Common, &mut kernel)
                    .map(|_| ());
                assert_eq!(refused, broken, "a chain head or link naming {link}");
                assert!(kernel.requests.is_empty(), "{link}: the kernel was asked");
                assert_eq!(allocator.allocation_descriptors_free(), free);
            });
            assert_eq!(failed, None, "{link}");
        }
    }

    /// A write that removes more than a maintained figure holds leaves the
    /// figure at zero and its table out of step instead of wrapping. The next
    /// request refuses by the name a broken chain or a full table carries,
    /// before anything reaches the kernel or a metadata page is mapped.
    #[test]
    fn a_figure_that_would_fall_below_zero_refuses_by_name_instead_of_wrapping() {
        use super::record_tables::ExtentDrift;
        type Short = fn(&mut ObjectAllocator);
        let broken = Err(AllocError::ArenaTableFull {
            limit: MAX_TASK_EXTENTS,
        });
        let cases: [(&str, Short); 3] = [
            ("present extent records", |allocator| {
                allocator.extents.drift_for_test(ExtentDrift::PresentShort)
            }),
            ("reusable extent bytes", |allocator| {
                allocator
                    .extents
                    .drift_for_test(ExtentDrift::FreeBytesShort)
            }),
            ("returned extents of one size", |allocator| {
                allocator
                    .extents
                    .drift_for_test(ExtentDrift::ReuseShort { size_bits: 13 })
            }),
        ];
        for (figure, short) in cases {
            let failed = room_chain_panic(move |allocator, arena, _, _| {
                seed_reusable_extents(allocator, ExtentKind::PrivateData, 13, 1);
                let returned = allocator.extents.walk_reusable(13).unwrap();
                short(allocator);
                allocator.extents.set(returned, None);
                let free = allocator.allocation_descriptors_free();
                let mut kernel = RecordingPrivateKernel::default();
                let refused = allocator
                    .acquire_private_in(
                        arena,
                        PrivateObjectKind::Granule,
                        sel4::cap_type::Granule::object_blueprint(),
                        ExtentSource::Common,
                        &mut kernel,
                    )
                    .map(|_| ());
                assert_eq!(refused, broken, "{figure}: the growth request");
                assert!(kernel.requests.is_empty(), "{figure}: the kernel was asked");
                assert_eq!(allocator.allocation_descriptors_free(), free);
                assert_eq!(
                    allocator.ensure_extent_descriptors(1),
                    broken,
                    "{figure}: a fresh extent record"
                );
            });
            assert_eq!(failed, None, "{figure}");
        }
        let failed = room_chain_panic(|allocator, arena, _, _| {
            let owned = allocator
                .allocations
                .iter()
                .position(|record| record.owner != u16::MAX)
                .unwrap();
            allocator.allocations.drift_short_for_test();
            allocator.allocations.set(owned, AllocationRecord::EMPTY);
            assert_eq!(
                allocator.provision_private_slots(arena, 1),
                Err(AllocError::ArenaSlotTableFull {
                    limit: MAX_TASK_ALLOCATIONS,
                }),
                "owned allocation records: a descriptor page"
            );
        });
        assert_eq!(failed, None, "owned allocation records");
    }
}
