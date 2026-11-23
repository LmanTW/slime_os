//! Task-private growable working memory (C10.1).
//!
//! A component's working memory is otherwise fixed at build time: its stack
//! comes from the image header and its `.data`/`.bss` from the linked ELF, so
//! every buffer must be sized for its worst case in every generation carrying
//! that component. This module is the mechanism that lifts that: one
//! task-private region, reserved as address space when the child VSpace is
//! built, backed page by page on demand, and returned in full when the task
//! dies.
//!
//! # What this is not
//!
//! It is deliberately *not* the C7 shared-buffer plane. Shared buffers exist to
//! move samples *between* components: each is a nameable, transferable,
//! loanable object the root retypes and tracks under a root-wide page ceiling.
//! Working memory is private, never transferred, never sealed, and needs no
//! physical contiguity — so there is no object here for a capability to
//! designate. What is bounded is *how many pages a task may hold*, which is a
//! budget, exactly as the stack is generation-sized and needs no capability.
//! Nothing here adds a seL4 object kind, a root-tracked object, or a right.
//!
//! # Shape
//!
//! The region is one window at a fixed base, grown only at its tail:
//!
//! * **The base never moves.** Native component images link at fixed virtual
//!   addresses and hold real machine pointers, so a growth that relocated the
//!   base would invalidate every live pointer. A growth past the reservation
//!   fails rather than moving. (WebAssembly runtimes may relocate a linear
//!   memory base precisely because Wasm code addresses by offset; native code
//!   has no such freedom.)
//! * **Address space is reserved at spawn, backing arrives on demand.** Leaf
//!   tables stay absent until a 4 KiB mapping needs them, so an aligned 2 MiB
//!   run can occupy the same slot directly. The task arena reserves the larger
//!   of the all-base-page and mixed-allocation constructions.
//! * **Growth is all-or-nothing.** A failure unwinds only this attempt's
//!   in-flight allocations: frames are unmapped and become reusable, while a
//!   newly mapped leaf table remains bound to its original span for retry.
//!   Backing extents and existing committed mappings remain owned.
//! * **Pages are user/read-write/execute-never, always.** No growth path can
//!   derive an executable mapping, so W^X holds by construction.
//! * **Allocation policy is userspace's.** The root tracks a page count and
//!   never an allocation; `free` is a free-list operation inside the component.

pub mod elastic;
#[cfg(any(
    slime_private_elastic,
    slime_private_fragmentation,
    slime_private_rollback,
    slime_private_conservation
))]
pub mod qualification;

use sel4::CapTypeForObjectOfFixedSize;

use crate::child_vspace::{
    GRANULE_SIZE, LARGE_FRAME_BYTES, LARGE_FRAME_PAGES, LARGE_FRAME_TYPE, private_leaf_table_type,
};
use crate::object_allocator::{
    AllocError, LeafSpanBits, ObjectAllocator, PrivateAllocation, PrivateObjectKind, TaskArenaId,
};

/// Target profile embedded into this root image by `build.rs`.
pub const IMAGE_TARGET_NAME: &str = env!("SLIME_TARGET_PROFILE");

const IMAGE_CAPACITY: (usize, usize) =
    boot_contracts::private_memory_budget::capacity_for(IMAGE_TARGET_NAME);

/// Pages one task's private region may ever hold in this target-qualified image.
pub const MAX_REGION_PAGES: usize = IMAGE_CAPACITY.0;

/// Pages one adaptive window may reserve: the spans one leaf-span record
/// tracks. A pool-relative maximum is clamped to it and a fixed maximum above
/// it is refused at admission, so no inventory size makes a window unplaceable.
pub const MAX_WINDOW_PAGES: usize =
    crate::object_allocator::MAX_WINDOW_SPANS * crate::child_vspace::LARGE_FRAME_PAGES;

/// The window a subject's admitted maximum reserves, or `None` when no
/// window can: a pool-relative maximum is clamped to [`MAX_WINDOW_PAGES`], a
/// fixed one above it is refused.
pub const fn window_pages(maximum: u64, pooled: bool) -> Option<usize> {
    if maximum <= MAX_WINDOW_PAGES as u64 {
        Some(maximum as usize)
    } else if pooled {
        Some(MAX_WINDOW_PAGES)
    } else {
        None
    }
}

/// Pages every live private region may hold together in this image.
pub const MAX_TOTAL_PAGES: usize = IMAGE_CAPACITY.1;

const _: () = assert!(
    MAX_REGION_PAGES == boot_contracts::private_memory_budget::capacity_for(IMAGE_TARGET_NAME).0,
    "private-memory reservation drifted from the image target's contract row"
);
const _: () = assert!(
    MAX_TOTAL_PAGES == boot_contracts::private_memory_budget::capacity_for(IMAGE_TARGET_NAME).1,
    "private-memory total ceiling drifted from the image target's contract row"
);

/// Why a growth was refused.
///
/// Four distinct causes, because a caller must be able to tell "I asked for
/// something impossible" from "the machine is full": an allocator that cannot
/// distinguish quota exhaustion from frame exhaustion cannot decide whether
/// retrying later could help. The root's own markers name the cause; the wire
/// status the caller sees stays the coarse class
/// `contracts/syscall-abi/v1` declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrowError {
    /// `pages + delta` does not fit a `usize`, or the delta itself does not fit
    /// the page-count representation. Refused before any arithmetic that could
    /// wrap into a small, plausible-looking request.
    DeltaOverflow { pages: usize, delta: usize },
    /// The growth would pass the reserved window. The base cannot move, so this
    /// is a refusal rather than a relocation.
    ReservationExceeded {
        pages: usize,
        delta: usize,
        reservation: usize,
    },
    /// The growth would pass this task's declared quota.
    QuotaExceeded {
        pages: usize,
        delta: usize,
        quota: usize,
    },
    /// The growth would pass the root-wide ceiling every live region shares.
    TotalExceeded {
        total: usize,
        delta: usize,
        ceiling: usize,
    },
    /// A frame could not be retyped or mapped. The attempt's own objects are
    /// unwound but retained: frames are unmapped and their typed records become
    /// reusable, while a mapped leaf table remains owned by its original span
    /// and unavailable to another span. No backing extent is revoked, so
    /// `allocated` pages of this attempt remain owned by the task for retry.
    Frames { allocated: usize, error: AllocError },
}

/// One task's private region: where it starts, how far it may grow, and how
/// much of it is currently backed.
///
/// `Copy`, because [`crate::task::Task`] is: the whole per-task record is a
/// fixed-size value the table stores inline. Leaf-table ownership is tracked
/// per 2 MiB span because large-frame spans and base-page spans may be
/// interleaved and failed transactions retain mapped tables for retry, but the
/// span bits themselves live in allocator-owned page-backed storage: a window
/// sized by policy is not bounded by the compiled target row, and a copy of a
/// region names the same window and therefore the same ownership record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    base: usize,
    reservation: usize,
    quota: usize,
    pages: usize,
    large_frames: usize,
    base_frames: usize,
    leaf_tables: usize,
    leaf_spans: LeafSpanBits,
    /// Backing for this region arrives per request from the common pool.
    ///
    /// A quota is a promise the construction path already paid for; an elastic
    /// maximum is permission to ask. The distinction is carried here so a
    /// region cannot be grown through the path that does not own its backing
    /// model.
    elastic: bool,
}

impl Region {
    /// A region no task can grow: no address space, no quota.
    ///
    /// The deny-by-default state, and what the fixture paths and any task the
    /// generation gives no quota hold. Deliberately not "reserved but
    /// zero-quota": a task with no quota should also not carry a window, so
    /// nothing can later mistake the reservation for permission.
    pub const DENIED: Self = Self {
        base: 0,
        reservation: 0,
        quota: 0,
        pages: 0,
        large_frames: 0,
        base_frames: 0,
        leaf_tables: 0,
        leaf_spans: LeafSpanBits::NONE,
        elastic: false,
    };

    /// Reserve a window of `reservation` pages at `base`, authorizing `quota`
    /// pages of growth into it.
    ///
    /// The one constructor for a region with a window, because the reservation
    /// is decided once — by the same layout the child's VSpace was built from —
    /// and every other property follows it. `elastic` selects which model funds
    /// the growth: a fixed quota is a promise the construction path already
    /// paid for, an elastic maximum is permission to ask.
    ///
    /// `quota` is clamped by the reservation rather than refused: the
    /// reservation is the address space the window physically holds and the
    /// quota is policy, so a policy asking for more than the window can hold is
    /// honoured up to the window. Admission refuses a fixed maximum above
    /// [`MAX_WINDOW_PAGES`] and clamps a pool-relative one; this clamp is the
    /// mechanism side of the same rule.
    ///
    /// Three refusals, all deny-by-default, because each would otherwise fail
    /// later with pages already committed:
    ///
    /// * A base that is not large-frame aligned. Leaf-table ownership is
    ///   tracked per 2 MiB span of the window, so a misaligned base would put
    ///   one span's pages under two leaf tables and the second would never be
    ///   priced or recorded.
    /// * A window whose end does not fit an address. Every later window and
    ///   page address derives from this sum, and they are unchecked because
    ///   this is where the check belongs.
    /// * A window with more spans than the allocator can track.
    pub(crate) fn reserve(
        allocator: &mut ObjectAllocator,
        base: usize,
        reservation: usize,
        quota: usize,
        elastic: bool,
    ) -> Result<Self, AllocError> {
        let spans = Self::admit_window(base, reservation)?;
        let leaf_spans = allocator.acquire_leaf_spans(spans)?;
        Ok(Self::with_spans(
            base,
            reservation,
            quota,
            elastic,
            leaf_spans,
        ))
    }

    /// Admit a window's shape, answering the spans it needs tracked.
    fn admit_window(base: usize, reservation: usize) -> Result<usize, AllocError> {
        if reservation == 0 || !base.is_multiple_of(LARGE_FRAME_BYTES) {
            return Err(AllocError::PrivateRegionWindow { base, reservation });
        }
        reservation
            .checked_mul(GRANULE_SIZE)
            .and_then(|bytes| base.checked_add(bytes))
            .ok_or(AllocError::PrivateRegionWindow { base, reservation })?;
        Ok(reservation.div_ceil(LARGE_FRAME_PAGES))
    }

    fn with_spans(
        base: usize,
        reservation: usize,
        quota: usize,
        elastic: bool,
        leaf_spans: LeafSpanBits,
    ) -> Self {
        Self {
            base,
            reservation,
            quota: if quota > reservation {
                reservation
            } else {
                quota
            },
            pages: 0,
            large_frames: 0,
            base_frames: 0,
            leaf_tables: 0,
            leaf_spans,
            elastic,
        }
    }

    pub const fn base(self) -> usize {
        self.base
    }

    /// Pages of address space the window can ever hold.
    pub const fn reservation(self) -> usize {
        self.reservation
    }

    pub const fn is_elastic(self) -> bool {
        self.elastic
    }

    /// Pages currently backed by a frame.
    pub const fn pages(self) -> usize {
        self.pages
    }

    pub const fn quota(self) -> usize {
        self.quota
    }

    pub const fn large_frames(self) -> usize {
        self.large_frames
    }

    pub const fn base_frames(self) -> usize {
        self.base_frames
    }

    pub const fn leaf_tables(self) -> usize {
        self.leaf_tables
    }

    fn has_leaf_table(self, span: usize) -> bool {
        self.leaf_spans.get(span)
    }

    fn mark_leaf_table(&mut self, span: usize) {
        if self.leaf_spans.set(span) {
            self.leaf_tables += 1;
        }
    }

    /// Bytes of address space the window spans, backed or not.
    ///
    /// Unchecked, like every other address this region derives: [`Self::reserve`]
    /// proved `base + reservation * GRANULE_SIZE` fits an address before the
    /// window existed, and the reservation never grows.
    pub const fn reserved_bytes(self) -> usize {
        self.reservation * GRANULE_SIZE
    }

    /// The window's address range, for the VSpace construction that reserves it
    /// and for the guard-placement arithmetic that keeps it clear of the image.
    pub const fn window(self) -> core::ops::Range<usize> {
        self.base..self.base + self.reservation * GRANULE_SIZE
    }

    /// Whether `range` runs into this window.
    ///
    /// The one question every *other* mapping path has to ask (C10.4). The
    /// window is reserved address space whose leaf frames arrive on demand, so
    /// before the allocator has grown into a page there is nothing mapped there
    /// and an unrelated `frame_map` at that address simply succeeds. What lands
    /// is then indistinguishable from private memory to the component holding
    /// it: its allocator hands the range out as heap and writes structured
    /// allocations over storage another component can reach, while a later
    /// growth maps a frame at an address the other table believes it owns.
    /// Neither table is wrong on its own terms, which is exactly why neither
    /// would report it.
    ///
    /// Tested against the whole reservation rather than the backed prefix,
    /// deliberately. Bounding it by the live page count would make the answer
    /// depend on how far this component's allocator happened to have grown, so
    /// the same generation would admit or refuse the same mapping depending on
    /// timing. The reservation is a fixed property of the VSpace, and refusing
    /// against it makes the two planes disjoint by construction rather than by
    /// schedule.
    ///
    /// A [`Self::DENIED`] region overlaps nothing: it carries no window, which
    /// is why a task with no quota is not a task with a hole in its address
    /// space that nothing may use.
    pub const fn overlaps(self, range: &core::ops::Range<usize>) -> bool {
        let window = self.window();
        window.start < window.end && range.start < window.end && window.start < range.end
    }

    /// Where the next grown page lands.
    const fn next_vaddr(self) -> usize {
        self.base + self.pages * GRANULE_SIZE
    }

    /// Check a growth against every bound *before* a frame is touched.
    ///
    /// Split out from [`Table::grow`] so the ordering of the four refusals is
    /// testable on the host without a kernel: which bound a caller hits decides
    /// which error it sees, and that ordering is part of the operation's
    /// contract.
    fn admit(self, delta: usize, total: usize) -> Result<(), GrowError> {
        let pages = self.pages;
        let Some(requested) = pages.checked_add(delta) else {
            return Err(GrowError::DeltaOverflow { pages, delta });
        };
        // Reservation before quota: the reservation is what the address space
        // can physically hold, so a request past it is malformed rather than
        // merely unaffordable, and reporting the affordable-but-impossible case
        // as a quota problem would tell a caller to wait for something that
        // will never happen. A task with no window is refused here too, which
        // is what deny-by-default means: no address space rather than a policy
        // number that could be raised.
        if requested > self.reservation {
            return Err(GrowError::ReservationExceeded {
                pages,
                delta,
                reservation: self.reservation,
            });
        }
        if requested > self.quota {
            return Err(GrowError::QuotaExceeded {
                pages,
                delta,
                quota: self.quota,
            });
        }
        let Some(requested_total) = total.checked_add(delta) else {
            return Err(GrowError::DeltaOverflow { pages, delta });
        };
        if requested_total > MAX_TOTAL_PAGES {
            return Err(GrowError::TotalExceeded {
                total,
                delta,
                ceiling: MAX_TOTAL_PAGES,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
impl Region {
    /// The same window, with its span record taken from the host-test store.
    pub(crate) fn reserve_for_test(
        base: usize,
        reservation: usize,
        quota: usize,
        elastic: bool,
    ) -> Result<Self, AllocError> {
        let spans = Self::admit_window(base, reservation)?;
        let leaf_spans = crate::object_allocator::host_leaf_spans(spans)
            .ok_or(AllocError::PrivateRegionSpans { spans, limit: 0 })?;
        Ok(Self::with_spans(
            base,
            reservation,
            quota,
            elastic,
            leaf_spans,
        ))
    }

    /// Apply a priced shape to this region without a kernel, for host tests of
    /// the pricing itself: the mapping paths stay the seL4 gates' to prove.
    fn commit_shape_for_test(&mut self, shape: elastic::Shape) {
        let mut page = self.pages;
        for _ in 0..shape.tables {
            self.mark_leaf_table(page / LARGE_FRAME_PAGES);
        }
        page += shape.pages();
        self.pages = page;
        self.large_frames += shape.large_frames;
        self.base_frames += shape.base_pages;
    }
}

pub(crate) trait PrivateMemoryKernel {
    fn revoke(&mut self, parent: sel4::cap::Untyped) -> Result<(), sel4::Error>;
    fn retype(
        &mut self,
        parent: sel4::cap::Untyped,
        blueprint: &sel4::ObjectBlueprint,
        slot: usize,
    ) -> Result<(), sel4::Error>;
    fn map_frame(
        &mut self,
        frame: sel4::cap::UnspecifiedPage,
        vspace: sel4::cap::VSpace,
        vaddr: usize,
        rights: sel4::CapRights,
        attrs: sel4::VmAttributes,
    ) -> Result<(), sel4::Error>;
    fn map_leaf(
        &mut self,
        table: sel4::cap::UnspecifiedIntermediateTranslationTable,
        ty: sel4::TranslationTableObjectType,
        vspace: sel4::cap::VSpace,
        vaddr: usize,
        attrs: sel4::VmAttributes,
    ) -> Result<(), sel4::Error>;
    fn unmap_frame(&mut self, frame: sel4::cap::UnspecifiedPage) -> Result<(), sel4::Error>;
}

struct NativePrivateMemoryKernel {
    #[cfg(slime_private_stress)]
    failure: Option<StressFailure>,
}

#[cfg(slime_private_stress)]
struct StressFailure {
    allocation: bool,
    remaining: usize,
}

#[cfg(slime_private_stress)]
static STRESS_MAP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
#[cfg(slime_private_stress)]
static STRESS_ALLOCATION: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

impl NativePrivateMemoryKernel {
    fn for_growth(_region: &Region, _delta: usize) -> Self {
        Self {
            #[cfg(slime_private_stress)]
            failure: {
                use core::sync::atomic::Ordering;
                if _region.quota == 65_536
                    && _region.pages == 512
                    && _delta == 1024
                    && STRESS_MAP.swap(false, Ordering::Relaxed)
                {
                    Some(StressFailure {
                        allocation: false,
                        remaining: 2,
                    })
                } else if _region.quota == 65_536
                    && _region.pages == 65_534
                    && _delta == 2
                    && STRESS_ALLOCATION.swap(false, Ordering::Relaxed)
                {
                    Some(StressFailure {
                        allocation: true,
                        remaining: 2,
                    })
                } else {
                    None
                }
            },
        }
    }

    #[cfg(slime_private_stress)]
    fn refuse(&mut self, allocation: bool) -> bool {
        let Some(failure) = self.failure.as_mut() else {
            return false;
        };
        if failure.allocation != allocation {
            return false;
        }
        failure.remaining -= 1;
        if failure.remaining != 0 {
            return false;
        }
        let (case, previous, delta, backed) = if allocation {
            ("allocation", 65_534, 2, 1)
        } else {
            ("map", 512, 1024, 512)
        };
        crate::diagnostic_println!(
            "SLIME_MEM stress growth case={case} previous={previous} delta={delta} backed={backed}"
        );
        self.failure = None;
        true
    }
}

impl PrivateMemoryKernel for NativePrivateMemoryKernel {
    fn revoke(&mut self, parent: sel4::cap::Untyped) -> Result<(), sel4::Error> {
        sel4::init_thread::slot::CNODE
            .cap()
            .absolute_cptr(sel4::CPtr::from_bits(parent.bits()))
            .revoke()
    }

    fn retype(
        &mut self,
        parent: sel4::cap::Untyped,
        blueprint: &sel4::ObjectBlueprint,
        slot: usize,
    ) -> Result<(), sel4::Error> {
        #[cfg(slime_private_stress)]
        if self.refuse(true) {
            return Err(sel4::Error::NotEnoughMemory);
        }
        crate::root_cspace::retype(parent, blueprint, slot, 1)
    }

    fn map_frame(
        &mut self,
        frame: sel4::cap::UnspecifiedPage,
        vspace: sel4::cap::VSpace,
        vaddr: usize,
        rights: sel4::CapRights,
        attrs: sel4::VmAttributes,
    ) -> Result<(), sel4::Error> {
        #[cfg(slime_private_stress)]
        if self.refuse(false) {
            return Err(sel4::Error::NotEnoughMemory);
        }
        frame.frame_map(vspace, vaddr, rights, attrs)
    }

    fn map_leaf(
        &mut self,
        table: sel4::cap::UnspecifiedIntermediateTranslationTable,
        ty: sel4::TranslationTableObjectType,
        vspace: sel4::cap::VSpace,
        vaddr: usize,
        attrs: sel4::VmAttributes,
    ) -> Result<(), sel4::Error> {
        table.generic_intermediate_translation_table_map(ty, vspace, vaddr, attrs)
    }

    fn unmap_frame(&mut self, frame: sel4::cap::UnspecifiedPage) -> Result<(), sel4::Error> {
        frame.frame_unmap()
    }
}

/// Every live private region, and the root-wide page count they share.
///
/// The table is indexed by nothing: each task owns its own [`Region`] inline,
/// and this holds only the aggregate the root-wide ceiling is enforced against.
/// Keeping the total here rather than recomputing it from the task table is
/// what makes the ceiling a single-writer invariant — a growth charges it and a
/// reclamation returns it, and no third party can disagree about the sum.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Table {
    total_pages: usize,
    grants: usize,
    grown_pages: usize,
    reclaimed_pages: usize,
}

impl Table {
    pub const fn new() -> Self {
        Self {
            total_pages: 0,
            grants: 0,
            grown_pages: 0,
            reclaimed_pages: 0,
        }
    }

    /// Pages backed across every live region.
    pub const fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Growth operations served, for the root's own accounting marker.
    pub const fn grants(&self) -> usize {
        self.grants
    }

    /// Pages ever granted, and pages ever returned. Their difference is
    /// [`Self::total_pages`], which is what makes a leak observable on serial
    /// rather than inferred from a frame count.
    pub const fn grown_pages(&self) -> usize {
        self.grown_pages
    }

    pub const fn reclaimed_pages(&self) -> usize {
        self.reclaimed_pages
    }

    /// Grow `region` by `delta` pages, answering the page count *before* the
    /// growth. A failed transaction does not change logical page charges or
    /// existing committed mappings and data. Translation structure mapped by
    /// the failed attempt may remain for a retry of the same fixed region.
    pub fn grow(
        &mut self,
        allocator: &mut ObjectAllocator,
        arena: TaskArenaId,
        vspace: sel4::cap::VSpace,
        region: &mut Region,
        delta: usize,
    ) -> Result<usize, GrowError> {
        let mut kernel = NativePrivateMemoryKernel::for_growth(region, delta);
        self.grow_with_kernel(allocator, arena, vspace, region, delta, &mut kernel)
    }

    pub(crate) fn grow_with_kernel<K: PrivateMemoryKernel>(
        &mut self,
        allocator: &mut ObjectAllocator,
        arena: TaskArenaId,
        vspace: sel4::cap::VSpace,
        region: &mut Region,
        delta: usize,
        kernel: &mut K,
    ) -> Result<usize, GrowError> {
        if region.elastic {
            return Err(GrowError::QuotaExceeded {
                pages: region.pages,
                delta,
                quota: region.quota,
            });
        }
        region.admit(delta, self.total_pages)?;
        let previous = region.pages;
        if delta == 0 {
            return Ok(previous);
        }
        // The fixed model's selection is unchanged: its quota is reserved whole
        // at construction, so a large frame is always placeable.
        let outcome = map_growth(
            allocator,
            arena,
            vspace,
            region,
            delta,
            GrowthPlan::elastic(),
            kernel,
        )?;
        allocator
            .commit_private_transaction(arena)
            .map_err(|error| GrowError::Frames {
                allocated: outcome.pages_backed,
                error,
            })?;
        self.record_growth(region, delta, outcome.large_frames, outcome.base_frames);
        Ok(previous)
    }

    /// Charge one settled growth to the region and the root-wide totals.
    ///
    /// Separated from the mapping loop because both backing models share the
    /// accounting and neither may charge before every page has real backing.
    pub(crate) fn record_growth(
        &mut self,
        region: &mut Region,
        delta: usize,
        large_frames: usize,
        base_frames: usize,
    ) {
        region.pages += delta;
        region.large_frames += large_frames;
        region.base_frames += base_frames;
        self.total_pages += delta;
        self.grown_pages += delta;
        self.grants += 1;
    }

    /// Return one dying task's pages to the root-wide total.
    ///
    /// The frames themselves are destroyed by the task-arena revoke every
    /// reclamation already performs — they were retyped from that arena's
    /// untyped, so nothing separate has to unmap them. What this returns is the
    /// *charge*, which is bookkeeping the revoke cannot see.
    ///
    /// Idempotent: reclaiming a region twice returns zero the second time, so a
    /// retried teardown cannot drive the total negative. The span-ownership
    /// record goes back to the allocator with the same call, because the window
    /// it describes is gone; the region keeps no handle to it.
    pub(crate) fn reclaim(
        &mut self,
        allocator: &mut ObjectAllocator,
        region: &mut Region,
    ) -> usize {
        let released = region.leaf_spans;
        let pages = self.reclaim_accounting(region);
        allocator.release_leaf_spans(released);
        pages
    }

    fn reclaim_accounting(&mut self, region: &mut Region) -> usize {
        let pages = region.pages;
        region.pages = 0;
        region.large_frames = 0;
        region.base_frames = 0;
        region.leaf_tables = 0;
        region.leaf_spans = LeafSpanBits::NONE;
        self.total_pages = self.total_pages.saturating_sub(pages);
        self.reclaimed_pages += pages;
        pages
    }
}

#[cfg(test)]
impl Table {
    /// The accounting half, for host tests that hold no allocator.
    pub(crate) fn reclaim_for_test(&mut self, region: &mut Region) -> usize {
        let released = region.leaf_spans;
        let pages = self.reclaim_accounting(region);
        crate::object_allocator::host_release_leaf_spans(released);
        pages
    }
}

/// Which frame sizes one growth is allowed to use.
///
/// The single mapping decision for a growth, resolved by the caller and then
/// consumed by pricing, acquisition and mapping alike. A guaranteed payload
/// takes [`Lane::BasePage`] so its promise never depends on an aligned 2 MiB
/// placement still existing when the page is finally asked for; elastic
/// payload keeps [`Lane::LargeFrame`], which is the selection every fixed and
/// elastic holder has always used.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Lane {
    #[default]
    LargeFrame,
    BasePage,
}

impl Lane {
    const fn allows_large_frames(self) -> bool {
        matches!(self, Self::LargeFrame)
    }
}

/// One growth's complete mapping decision, resolved once by the caller.
///
/// Pricing, acquisition, certification and mapping all read this same value.
/// `guaranteed_pages` is a prefix of the growth rather than a set of page
/// numbers because a transaction redeems its entitlement before it spends the
/// pool, which is also the order the ledger charges them in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GrowthPlan {
    pub lane: Lane,
    pub guaranteed_pages: usize,
    pub reservation: Option<crate::object_allocator::guarantee_vault::ReservationId>,
}

impl GrowthPlan {
    /// Ordinary growth: every page from the common pool, large frames allowed.
    pub const fn elastic() -> Self {
        Self {
            lane: Lane::LargeFrame,
            guaranteed_pages: 0,
            reservation: None,
        }
    }

    /// Where the `offset`-th page of this growth must be retyped from.
    const fn source(self, offset: usize) -> crate::object_allocator::ExtentSource {
        match self.reservation {
            Some(id) if offset < self.guaranteed_pages => {
                crate::object_allocator::ExtentSource::Guaranteed(id)
            }
            _ => crate::object_allocator::ExtentSource::Common,
        }
    }
}

/// What one growth's mappings cost, once they exist.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GrowthOutcome {
    pub(crate) pages_backed: usize,
    pub(crate) large_frames: usize,
    pub(crate) base_frames: usize,
}

/// Back `delta` further pages of `region`, mapping each one as it is taken.
///
/// Shared by both backing models: what differs between them is where the
/// resources came from and who authorized them, not how a page is mapped. The
/// caller settles the transaction — this leaves every mapping in flight, so a
/// failure unwinds this attempt alone and no charge is made against a page
/// that is not yet backed.
pub(crate) fn map_growth<K: PrivateMemoryKernel>(
    allocator: &mut ObjectAllocator,
    arena: TaskArenaId,
    vspace: sel4::cap::VSpace,
    region: &mut Region,
    delta: usize,
    plan: GrowthPlan,
    kernel: &mut K,
) -> Result<GrowthOutcome, GrowError> {
    let lane = plan.lane;
    let previous = region.pages;
    let mut pages_backed = 0;
    let mut large_frames = 0;
    let mut base_frames = 0;
    {
        // Each 2 MiB span has its own leaf table when base pages are used.
        // Failed growth retains a mapped table bound to that span for retry,
        // and large-frame spans may precede it, so presence is tracked by span.
        let mut span = previous / LARGE_FRAME_PAGES;
        let mut leaf_available = region.has_leaf_table(span);
        while pages_backed < delta {
            let page = previous + pages_backed;
            if page != previous && page.is_multiple_of(LARGE_FRAME_PAGES) {
                span = page / LARGE_FRAME_PAGES;
                leaf_available = region.has_leaf_table(span);
            }
            let vaddr = region.base + page * GRANULE_SIZE;
            let remaining = delta - pages_backed;
            // The same predicate `Region::shape_in` priced, reading the same
            // lane. Deciding it independently here is how a mapper could take
            // a large frame the transaction was never charged for.
            let large = lane.allows_large_frames()
                && !leaf_available
                && vaddr.is_multiple_of(LARGE_FRAME_BYTES)
                && remaining >= LARGE_FRAME_PAGES;
            // The page's own source, and the same source for the leaf table
            // that page needs: a guaranteed page whose table came from the
            // pool would leave the guarantee unredeemable after exactly the
            // pool exhaustion it was supposed to be immune to.
            let source = plan.source(pages_backed);
            let result = if large {
                back_large(
                    allocator,
                    arena,
                    vspace,
                    vaddr,
                    previous == 0 && delta == region.quota,
                    source,
                    kernel,
                )
            } else {
                if !leaf_available {
                    match back_leaf_table(allocator, arena, vspace, vaddr, source, kernel) {
                        Ok(table) => {
                            region.mark_leaf_table(span);
                            if let Err(error) =
                                allocator.mark_private_in_flight(arena, table.allocation, true)
                            {
                                let _ = allocator.unwind_private_transaction(arena, kernel);
                                return Err(GrowError::Frames {
                                    allocated: pages_backed,
                                    error,
                                });
                            }
                            leaf_available = true;
                        }
                        Err(error) => {
                            return Err(GrowError::Frames {
                                allocated: pages_backed,
                                error: match allocator.unwind_private_transaction(arena, kernel) {
                                    Ok(()) => error,
                                    Err(cleanup) => cleanup,
                                },
                            });
                        }
                    }
                }
                back_page(allocator, arena, vspace, vaddr, source, kernel)
            };
            match result {
                Ok(backing) => {
                    let pages = backing.pages;
                    if let Err(error) =
                        allocator.mark_private_in_flight(arena, backing.allocation, true)
                    {
                        let _ = allocator.unwind_private_transaction(arena, kernel);
                        return Err(GrowError::Frames {
                            allocated: pages_backed,
                            error,
                        });
                    }
                    pages_backed += pages;
                    if pages == LARGE_FRAME_PAGES {
                        large_frames += 1;
                    } else {
                        base_frames += pages;
                    }
                }
                Err(error) => {
                    return Err(GrowError::Frames {
                        allocated: pages_backed,
                        error: match allocator.unwind_private_transaction(arena, kernel) {
                            Ok(()) => error,
                            Err(cleanup) => cleanup,
                        },
                    });
                }
            }
        }
    }
    Ok(GrowthOutcome {
        pages_backed,
        large_frames,
        base_frames,
    })
}

/// One mapping an in-flight growth has taken. Persistent transaction state is
/// held in the allocator's capacity-scaled descriptor pool.
struct Backing {
    allocation: PrivateAllocation,
    pages: usize,
}

fn back_leaf_table<K: PrivateMemoryKernel>(
    allocator: &mut ObjectAllocator,
    arena: TaskArenaId,
    vspace: sel4::cap::VSpace,
    vaddr: usize,
    source: crate::object_allocator::ExtentSource,
    kernel: &mut K,
) -> Result<Backing, AllocError> {
    let ty = private_leaf_table_type();
    let size_bits = ty.blueprint().physical_size_bits();
    let allocation = allocator.acquire_private_in(
        arena,
        PrivateObjectKind::LeafTable,
        ty.blueprint(),
        source,
        kernel,
    )?;
    let table = allocation
        .cap()
        .cast::<sel4::cap_type::UnspecifiedIntermediateTranslationTable>();
    if !allocation.mapped()
        && let Err(error) = kernel.map_leaf(table, ty, vspace, vaddr, sel4::VmAttributes::default())
    {
        allocator.reset_private_in(arena, allocation)?;
        return Err(AllocError::Retype { size_bits, error });
    }
    Ok(Backing {
        allocation,
        pages: 0,
    })
}

fn back_page<K: PrivateMemoryKernel>(
    allocator: &mut ObjectAllocator,
    arena: TaskArenaId,
    vspace: sel4::cap::VSpace,
    vaddr: usize,
    source: crate::object_allocator::ExtentSource,
    kernel: &mut K,
) -> Result<Backing, AllocError> {
    let size_bits = sel4::FrameObjectType::GRANULE.bits();
    let allocation = allocator.acquire_private_in(
        arena,
        PrivateObjectKind::Granule,
        sel4::cap_type::Granule::object_blueprint(),
        source,
        kernel,
    )?;
    let frame = allocation.cap().cast::<sel4::cap_type::UnspecifiedPage>();
    if !allocation.mapped()
        && let Err(error) = kernel.map_frame(
            frame,
            vspace,
            vaddr,
            sel4::CapRights::read_write(),
            crate::vm_attributes::data(),
        )
    {
        allocator.reset_private_in(arena, allocation)?;
        return Err(AllocError::Retype { size_bits, error });
    }
    Ok(Backing {
        allocation,
        pages: 1,
    })
}

fn back_large<K: PrivateMemoryKernel>(
    allocator: &mut ObjectAllocator,
    arena: TaskArenaId,
    vspace: sel4::cap::VSpace,
    vaddr: usize,
    #[cfg_attr(not(slime_private_fail_large_map), allow(unused_variables))]
    first_of_full_window: bool,
    source: crate::object_allocator::ExtentSource,
    kernel: &mut K,
) -> Result<Backing, AllocError> {
    let size_bits = LARGE_FRAME_TYPE.bits();
    let allocation = allocator.acquire_private_in(
        arena,
        PrivateObjectKind::LargeFrame,
        LARGE_FRAME_TYPE.blueprint(),
        source,
        kernel,
    )?;
    let frame = allocation.cap().cast::<sel4::cap_type::UnspecifiedPage>();
    // Injected on the *first* large frame of a growth that starts at the window
    // base and asks for the whole quota — the aligned full-window request whose
    // conversion to base pages this arm exists to prove. Scoped that narrowly
    // because the injection is a one-shot: once any holder with a multi-span
    // quota takes a large frame, an unscoped flag lands on whichever growth the
    // scheduler ran first, and the case under test never sees its failure.
    #[cfg(slime_private_fail_large_map)]
    if first_of_full_window
        && !allocation.mapped()
        && crate::object_allocator::take_forced_private_large_map_failure()
    {
        allocator.reset_private_in(arena, allocation)?;
        return Err(AllocError::Retype {
            size_bits,
            error: sel4::Error::NotEnoughMemory,
        });
    }
    if !allocation.mapped()
        && let Err(error) = kernel.map_frame(
            frame,
            vspace,
            vaddr,
            sel4::CapRights::read_write(),
            crate::vm_attributes::data(),
        )
    {
        allocator.reset_private_in(arena, allocation)?;
        return Err(AllocError::Retype { size_bits, error });
    }
    Ok(Backing {
        allocation,
        pages: LARGE_FRAME_PAGES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window limit is exactly what the span record admits: the largest
    /// window reserves, one span more is refused, a pool-relative maximum past
    /// it is clamped and a fixed one is refused.
    #[test]
    fn a_maximum_beyond_one_window_is_clamped_when_pooled_and_refused_when_fixed() {
        extern crate std;
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut allocator = crate::object_allocator::ObjectAllocator::empty();
                let limit = MAX_WINDOW_PAGES;
                assert!(Region::reserve(&mut allocator, 0x40_0000, limit, limit, true).is_ok());
                assert!(matches!(
                    Region::reserve(
                        &mut allocator,
                        0x40_0000,
                        limit + LARGE_FRAME_PAGES,
                        limit,
                        true
                    ),
                    Err(AllocError::PrivateRegionSpans { .. })
                ));
                let pool = 64u64 << 30 >> 12;
                assert_eq!(window_pages(pool, true), Some(limit));
                assert_eq!(window_pages(pool, false), None);
                assert_eq!(window_pages(limit as u64, false), Some(limit));
                assert_eq!(window_pages(4096, true), Some(4096));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// A window of the compiled per-region capacity with an 8-page quota, so
    /// the quota bound and the reservation bound stay distinguishable.
    fn region() -> Region {
        reserved(0x1000_0000, MAX_REGION_PAGES, 8)
    }

    fn reserved(base: usize, reservation: usize, quota: usize) -> Region {
        Region::reserve_for_test(base, reservation, quota, false).expect("host test window")
    }

    #[test]
    fn a_denied_region_has_no_window_and_no_quota() {
        let denied = Region::DENIED;
        assert_eq!(denied.quota(), 0);
        assert_eq!(denied.pages(), 0);
        assert_eq!(denied.reserved_bytes(), 0);
        assert!(denied.window().is_empty());
        // Deny-by-default is the whole point: a task the generation does not
        // name grows nothing, and it fails on the reservation rather than
        // reaching a quota comparison against zero.
        assert_eq!(
            denied.admit(1, 0),
            Err(GrowError::ReservationExceeded {
                pages: 0,
                delta: 1,
                reservation: 0,
            })
        );
    }

    #[test]
    fn a_zero_delta_is_admitted_even_on_a_denied_region() {
        // A size query allocates nothing, so refusing it would force an
        // allocator with no quota to guess its own extent.
        assert_eq!(Region::DENIED.admit(0, 0), Ok(()));
        assert_eq!(Region::DENIED.admit(0, MAX_TOTAL_PAGES), Ok(()));
    }

    #[test]
    fn a_quota_is_clamped_to_the_reservation_never_raised_past_it() {
        let wide = reserved(0x1000_0000, LARGE_FRAME_PAGES, LARGE_FRAME_PAGES * 4);
        assert_eq!(wide.quota(), LARGE_FRAME_PAGES);
        assert_eq!(wide.reserved_bytes(), LARGE_FRAME_PAGES * GRANULE_SIZE);
    }

    #[test]
    fn a_malformed_window_is_refused_before_any_address_derives_from_it() {
        // Misaligned base: span ownership is indexed from it.
        assert!(Region::reserve_for_test(0x1000_0000 + GRANULE_SIZE, 8, 8, false).is_err());
        // Empty window: a region with a base and no reservation would answer
        // an empty `window()` while still claiming an address.
        assert!(Region::reserve_for_test(0x1000_0000, 0, 0, false).is_err());
        // A window whose end does not fit an address.
        assert!(Region::reserve_for_test(0x1000_0000, usize::MAX, 1, false).is_err());
    }

    #[test]
    fn the_window_starts_at_the_base_and_spans_the_whole_reservation() {
        let region = region();
        assert_eq!(region.base(), 0x1000_0000);
        assert_eq!(region.window().start, 0x1000_0000);
        assert_eq!(
            region.window().end,
            0x1000_0000 + MAX_REGION_PAGES * GRANULE_SIZE
        );
        assert_eq!(region.next_vaddr(), 0x1000_0000);
        // The reservation is the window the caller asked for, not a compiled
        // constant: a narrower policy yields a narrower window.
        let narrow = reserved(0x1000_0000, LARGE_FRAME_PAGES, LARGE_FRAME_PAGES);
        assert_eq!(
            narrow.window().end,
            0x1000_0000 + LARGE_FRAME_PAGES * GRANULE_SIZE
        );
    }

    #[test]
    fn a_mapping_anywhere_in_the_reservation_overlaps_even_where_no_page_is_backed() {
        let region = region();
        let window = region.window();
        // Nothing is backed here at all: `pages()` is zero. The whole point is
        // that an unbacked address inside the window is still not available to
        // another mapping, because whether a page has been grown into is a
        // property of when the check runs rather than of the address space.
        assert_eq!(region.pages(), 0);
        assert!(region.overlaps(&(window.start..window.start + GRANULE_SIZE)));
        assert!(region.overlaps(&(window.end - GRANULE_SIZE..window.end)));
        // A range straddling either boundary overlaps: the first byte inside is
        // enough, and a mapping is refused whole rather than clipped.
        assert!(region.overlaps(&(window.start - GRANULE_SIZE..window.start + GRANULE_SIZE)));
        assert!(region.overlaps(&(window.end - GRANULE_SIZE..window.end + GRANULE_SIZE)));
        // And one spanning it entirely, which a naive containment test misses.
        assert!(region.overlaps(&(window.start - GRANULE_SIZE..window.end + GRANULE_SIZE)));
    }

    #[test]
    fn a_mapping_touching_either_boundary_from_outside_does_not_overlap() {
        let region = region();
        let window = region.window();
        // Half-open on both ends: the page ending exactly at the base and the
        // one starting exactly at the end are both legal. Off-by-one here would
        // refuse a component the page immediately below its own window, which
        // `child_vspace` deliberately leaves as the guard granule.
        assert!(!region.overlaps(&(window.start - GRANULE_SIZE..window.start)));
        assert!(!region.overlaps(&(window.end..window.end + GRANULE_SIZE)));
        // An empty range at the base names no byte and so takes nothing.
        assert!(!region.overlaps(&(window.start..window.start)));
    }

    #[test]
    fn a_denied_region_overlaps_nothing_it_has_no_window_to_defend() {
        // A task with no quota carries no reservation, so there is no hole in
        // its address space and no address another mapping may not use. Were
        // this to answer `true` for the zero range, every mapping by every
        // component with no declared quota would be refused.
        let denied = Region::DENIED;
        assert!(!denied.overlaps(&(0..GRANULE_SIZE)));
        assert!(!denied.overlaps(&(0..usize::MAX)));
    }

    #[test]
    fn growth_within_the_quota_is_admitted_and_the_quota_edge_is_inclusive() {
        let region = region();
        assert_eq!(region.admit(1, 0), Ok(()));
        assert_eq!(region.admit(8, 0), Ok(()));
        assert_eq!(
            region.admit(9, 0),
            Err(GrowError::QuotaExceeded {
                pages: 0,
                delta: 9,
                quota: 8,
            })
        );
    }

    #[test]
    fn a_delta_that_would_overflow_the_page_count_is_refused_before_any_bound() {
        let mut region = region();
        region.pages = 3;
        assert_eq!(
            region.admit(usize::MAX, 0),
            Err(GrowError::DeltaOverflow {
                pages: 3,
                delta: usize::MAX,
            })
        );
    }

    #[test]
    fn the_reservation_is_reported_before_the_quota() {
        // Deny-by-default is about address space: a task the generation does
        // not name has no window, and reporting a zero quota would suggest a
        // number that could be raised.
        assert!(matches!(
            Region::DENIED.admit(1, 0),
            Err(GrowError::ReservationExceeded { reservation: 0, .. })
        ));
        // A holder whose window is narrower than its request is refused by the
        // window, whatever its quota says.
        let mut wide = reserved(0x1000_0000, MAX_REGION_PAGES, MAX_REGION_PAGES);
        wide.quota = MAX_REGION_PAGES * 2;
        wide.pages = MAX_REGION_PAGES;
        assert!(matches!(
            wide.admit(1, 0),
            Err(GrowError::ReservationExceeded { .. })
        ));
        // A holder still inside its window is refused by the quota policy set.
        let mut narrow = reserved(0x1000_0000, MAX_REGION_PAGES, LARGE_FRAME_PAGES);
        narrow.pages = LARGE_FRAME_PAGES;
        assert!(matches!(
            narrow.admit(1, 0),
            Err(GrowError::QuotaExceeded { .. })
        ));
    }

    #[test]
    fn the_root_wide_ceiling_is_checked_after_the_per_task_bounds() {
        let region = region();
        assert_eq!(
            region.admit(4, MAX_TOTAL_PAGES - 2),
            Err(GrowError::TotalExceeded {
                total: MAX_TOTAL_PAGES - 2,
                delta: 4,
                ceiling: MAX_TOTAL_PAGES,
            })
        );
        assert_eq!(region.admit(2, MAX_TOTAL_PAGES - 2), Ok(()));
    }

    #[test]
    fn reclaiming_a_region_returns_its_pages_and_is_idempotent() {
        let mut table = Table::new();
        let mut region = reserved(0x1000_0000, MAX_REGION_PAGES, 8);
        // The commit half of `grow` without a kernel: the host cannot map a
        // frame, so the accounting is driven directly and the mapping path
        // stays the seL4 gate's to prove.
        region.pages = 5;
        table.total_pages = 5;
        table.grown_pages = 5;
        assert_eq!(table.reclaim_for_test(&mut region), 5);
        assert_eq!(table.total_pages(), 0);
        assert_eq!(table.reclaimed_pages(), 5);
        assert_eq!(region.pages(), 0);
        // A failed initial growth may retain its mapped leaf without charging a
        // page. Teardown must clear that translation state without inventing a
        // grant or reclamation. The span record went back to the allocator with
        // the first reclaim, so a region that has been torn down owns no spans
        // at all rather than silently writing into a record another region may
        // now hold.
        let mut live = reserved(0x2000_0000, MAX_REGION_PAGES, 8);
        live.mark_leaf_table(1);
        assert!(live.has_leaf_table(1));
        region.mark_leaf_table(1);
        assert!(!region.has_leaf_table(1));
        assert_eq!(table.reclaim_for_test(&mut region), 0);
        assert_eq!(region.leaf_tables(), 0);
        assert!(live.has_leaf_table(1), "a live region keeps its own spans");
        assert_eq!(table.total_pages(), 0);
        assert_eq!(table.grown_pages(), 5);
        assert_eq!(table.reclaimed_pages(), 5);
        assert_eq!(table.grants(), 0);
        // A retried teardown must not drive the total negative.
        assert_eq!(table.reclaim_for_test(&mut region), 0);
        assert_eq!(table.total_pages(), 0);
        assert_eq!(table.reclaimed_pages(), 5);
    }

    #[test]
    fn one_tasks_exhaustion_leaves_another_tasks_ceiling_intact() {
        // The root-wide total is shared; the per-task quota is not. A task at
        // its own ceiling must not lower anyone else's.
        let mut exhausted = reserved(0x1000_0000, MAX_REGION_PAGES, 4);
        exhausted.pages = 4;
        let untouched = reserved(0x2000_0000, MAX_REGION_PAGES, 4);
        assert_eq!(
            exhausted.admit(1, 4),
            Err(GrowError::QuotaExceeded {
                pages: 4,
                delta: 1,
                quota: 4,
            })
        );
        assert_eq!(untouched.admit(4, 4), Ok(()));
    }
}
