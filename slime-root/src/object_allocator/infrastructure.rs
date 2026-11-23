//! Bootstrap ownership independent of task descriptors and preserved prefixes.
//! An adopted ordinary untyped is exclusively infrastructure-owned. Its pin
//! prevents cursor reset; alignment prefixes remain charged to this owner.

use super::{AllocError, UntypedRegion, plan_allocation};

pub(super) const METADATA_BASE: usize = 1usize << 37;
pub(super) const METADATA_END: usize = 1usize << 38;
const EMERGENCY_SLOTS: usize = 64;
const MAX_TRANSACTION_OBJECTS: usize = 6 + 2 * sel4::vspace_levels::NUM_LEVELS + 4;
const _: () = assert!(MAX_TRANSACTION_OBJECTS < EMERGENCY_SLOTS);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Reserved,
    Owned { bytes: usize },
}

pub(super) struct Infrastructure {
    source: Option<UntypedRegion>,
    retired_sources: [Option<UntypedRegion>; super::MAX_KERNEL_UNTYPEDS],
    retired_len: usize,
    slots: [SlotState; EMERGENCY_SLOTS],
    base: usize,
    alignment_bytes: usize,
    object_bytes: usize,
    owned_bytes: usize,
    pinned: bool,
    mapping: MappingTransaction,
    node: Option<(usize, usize, usize, bool)>,
    nodes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MappingOwnership {
    pub address: usize,
    pub frame: usize,
    pub tables: [Option<usize>; sel4::vspace_levels::NUM_LEVELS],
}

#[derive(Clone, Copy)]
struct MappingTransaction {
    address: Option<usize>,
    frame: Option<usize>,
    tables: [Option<usize>; sel4::vspace_levels::NUM_LEVELS],
    mapped: bool,
}

impl MappingTransaction {
    const EMPTY: Self = Self {
        address: None,
        frame: None,
        tables: [None; sel4::vspace_levels::NUM_LEVELS],
        mapped: false,
    };
}

impl Infrastructure {
    pub const fn new() -> Self {
        Self {
            source: None,
            retired_sources: [None; super::MAX_KERNEL_UNTYPEDS],
            retired_len: 0,
            slots: [SlotState::Free; EMERGENCY_SLOTS],
            base: 0,
            alignment_bytes: 0,
            object_bytes: 0,
            owned_bytes: 0,
            pinned: false,
            mapping: MappingTransaction::EMPTY,
            node: None,
            nodes: 0,
        }
    }

    pub fn needs_source(&self, bytes: usize) -> bool {
        self.remaining_bytes() < bytes
    }

    /// Transfer the remaining tail of an ordinary source whose cursor is
    /// already pinned by retained descendants. The caller must stop allocating
    /// from that tail; prior descendants retain their independent ownership.
    pub fn adopt_pinned_source(&mut self, source: UntypedRegion) -> Result<(), AllocError> {
        if source.watermark == 0 {
            return Err(AllocError::NoKernelUntyped);
        }
        self.adopt_source(source)
    }

    /// Transfer a whole returned extent, whose kernel cursor restarts at zero.
    ///
    /// No cursor pin is needed: nothing retyped from an infrastructure source
    /// is ever deleted, so its first object pins the cursor for the source's
    /// lifetime, exactly as the retained descendants of an ordinary tail do.
    pub fn adopt_extent_source(&mut self, source: UntypedRegion) -> Result<(), AllocError> {
        if source.watermark != 0 {
            return Err(AllocError::NoKernelUntyped);
        }
        self.adopt_source(source)
    }

    fn adopt_source(&mut self, source: UntypedRegion) -> Result<(), AllocError> {
        if !self.pinned
            || source.remaining() == 0
            || self.retired_len == self.retired_sources.len()
            || self.source.is_some_and(|current| current.cap == source.cap)
            || self.retired_sources[..self.retired_len]
                .iter()
                .flatten()
                .any(|old| old.cap == source.cap)
        {
            return Err(AllocError::NoKernelUntyped);
        }
        let owned_bytes = self.owned_bytes.checked_add(source.remaining()).ok_or(
            AllocError::AdaptiveFunding {
                resource: "arithmetic",
                required: 0,
                available: 0,
            },
        )?;
        self.retired_sources[self.retired_len] = self.source;
        self.retired_len += 1;
        self.owned_bytes = owned_bytes;
        self.source = Some(source);
        Ok(())
    }

    pub fn bootstrap_bytes() -> usize {
        let cnode = crate::root_cspace::leaf_blueprint().physical_size_bits();
        (6 * (1usize << cnode) + (2 * sel4::vspace_levels::NUM_LEVELS + 4) * super::GRANULE_BYTES)
            .next_power_of_two()
    }

    pub const fn bootstrap_slots() -> usize {
        EMERGENCY_SLOTS
    }

    /// The caller removes the complete source and slot range from every other
    /// allocator before calling this method. Failed initialization retains them.
    pub fn initialize(&mut self, source: UntypedRegion, base: usize) -> Result<(), AllocError> {
        self.initialize_with(source, base, |parent, blueprint, slot| {
            crate::root_cspace::retype(parent, blueprint, slot, 1)
        })
    }

    fn initialize_with(
        &mut self,
        source: UntypedRegion,
        base: usize,
        mut retype: impl FnMut(
            sel4::cap::Untyped,
            &sel4::ObjectBlueprint,
            usize,
        ) -> Result<(), sel4::Error>,
    ) -> Result<(), AllocError> {
        if self.source.is_some()
            || source.watermark != 0
            || base.checked_add(EMERGENCY_SLOTS).is_none()
        {
            return Err(AllocError::NoKernelUntyped);
        }
        self.owned_bytes = source.capacity();
        self.source = Some(source);
        self.base = base;
        let blueprint = sel4::ObjectBlueprint::Untyped {
            size_bits: sel4::sys::seL4_MinUntypedBits as usize,
        };
        self.retype_with(blueprint, &mut retype)?;
        self.pinned = true;
        Ok(())
    }

    pub fn allocate(&mut self, blueprint: sel4::ObjectBlueprint) -> Result<usize, AllocError> {
        self.allocate_with(blueprint, |parent, blueprint, slot| {
            crate::root_cspace::retype(parent, blueprint, slot, 1)
        })
    }

    fn allocate_with(
        &mut self,
        blueprint: sel4::ObjectBlueprint,
        mut retype: impl FnMut(
            sel4::cap::Untyped,
            &sel4::ObjectBlueprint,
            usize,
        ) -> Result<(), sel4::Error>,
    ) -> Result<usize, AllocError> {
        if !self.pinned {
            return Err(AllocError::NoKernelUntyped);
        }
        self.retype_with(blueprint, &mut retype)
    }

    fn retype_with(
        &mut self,
        blueprint: sel4::ObjectBlueprint,
        mut retype: impl FnMut(
            sel4::cap::Untyped,
            &sel4::ObjectBlueprint,
            usize,
        ) -> Result<(), sel4::Error>,
    ) -> Result<usize, AllocError> {
        let source = self.source.ok_or(AllocError::NoKernelUntyped)?;
        let bits = blueprint.physical_size_bits();
        let (start, end) = plan_allocation(source.watermark, source.capacity(), bits).ok_or(
            AllocError::UntypedExhausted {
                size_bits: bits,
                remaining: source.remaining(),
            },
        )?;
        let index = self
            .slots
            .iter()
            .position(|state| *state == SlotState::Free)
            .ok_or(AllocError::SlotsExhausted {
                allocated: EMERGENCY_SLOTS,
            })?;
        self.slots[index] = SlotState::Reserved;
        let slot = self.base + index;
        if let Err(error) = retype(source.cap, &blueprint, slot) {
            self.slots[index] = SlotState::Free;
            return Err(AllocError::Retype {
                size_bits: bits,
                error,
            });
        }
        let bytes = 1usize << bits;
        self.slots[index] = SlotState::Owned { bytes };
        self.source.as_mut().expect("source retained").watermark = end;
        self.alignment_bytes += start - source.watermark;
        self.object_bytes += bytes;
        Ok(slot)
    }

    /// Map one page in a root-owned, previously reserved virtual window.
    /// The caller must exclude all other mappings from that address and retain
    /// returned frame/table capabilities. A failed operation resumes in place;
    /// it cannot begin another address while its ownership is pending.
    pub fn map_page(&mut self, address: usize) -> Result<usize, AllocError> {
        if !(METADATA_BASE..METADATA_END).contains(&address)
            || !address.is_multiple_of(super::GRANULE_BYTES)
            || self
                .mapping
                .address
                .is_some_and(|pending| pending != address)
        {
            return Err(AllocError::NoKernelUntyped);
        }
        self.mapping.address = Some(address);
        if self.mapping.frame.is_none() {
            self.mapping.frame = Some(self.allocate(sel4::FrameObjectType::GRANULE.blueprint())?);
        }
        let vspace = sel4::init_thread::slot::VSPACE.cap();
        let frame_slot = self.mapping.frame.expect("frame retained");
        let frame = sel4::cap::Granule::from_bits(frame_slot as _);
        while !self.mapping.mapped {
            match frame.frame_map(
                vspace,
                address,
                sel4::CapRights::read_write(),
                crate::vm_attributes::data(),
            ) {
                Ok(()) => self.mapping.mapped = true,
                Err(sel4::Error::FailedLookup) => {
                    // seL4's mapping failure ABI returns missing translation
                    // bits in MR2. Read it before any subsequent invocation.
                    let missing_bits =
                        sel4::with_ipc_buffer(|buffer| buffer.msg_regs()[2] as usize);
                    let level = (1..sel4::vspace_levels::NUM_LEVELS)
                        .find(|level| sel4::vspace_levels::span_bits(*level) == missing_bits)
                        .ok_or(AllocError::NoKernelUntyped)?;
                    let ty = sel4::TranslationTableObjectType::from_level(level)
                        .ok_or(AllocError::NoKernelUntyped)?;
                    if self.mapping.tables[level].is_none() {
                        self.mapping.tables[level] = Some(self.allocate(ty.blueprint())?);
                    }
                    let slot = self.mapping.tables[level].expect("table retained");
                    sel4::cap::UnspecifiedIntermediateTranslationTable::from_bits(slot as _)
                        .generic_intermediate_translation_table_map(
                            ty,
                            vspace,
                            address,
                            sel4::VmAttributes::default(),
                        )
                        .map_err(|error| AllocError::ArenaCleanup { slot, error })?;
                }
                Err(error) => {
                    return Err(AllocError::ArenaCleanup {
                        slot: frame_slot,
                        error,
                    });
                }
            }
        }
        Ok(frame_slot)
    }

    /// Transfer the completed transaction into durable metadata before another
    /// page may be mapped. The callback must record all capabilities atomically;
    /// a refusal leaves this transaction intact and retryable.
    pub fn finish_mapping(
        &mut self,
        mut retain: impl FnMut(MappingOwnership) -> Result<(), AllocError>,
    ) -> Result<(), AllocError> {
        if !self.mapping.mapped {
            return Err(AllocError::NoKernelUntyped);
        }
        let owned = MappingOwnership {
            address: self.mapping.address.ok_or(AllocError::NoKernelUntyped)?,
            frame: self.mapping.frame.ok_or(AllocError::NoKernelUntyped)?,
            tables: self.mapping.tables,
        };
        retain(owned)?;
        self.mapping = MappingTransaction::EMPTY;
        Ok(())
    }

    /// Return the new durable CNode path while keeping a temporary capability
    /// owned if installation or deletion fails.
    pub fn install_node(&mut self, prefix: usize, depth: usize) -> Result<(), AllocError> {
        if let Some((pending_prefix, pending_depth, _, _)) = self.node {
            if pending_prefix != prefix || pending_depth != depth {
                return Err(AllocError::NoKernelUntyped);
            }
        } else {
            let slot = self.allocate(crate::root_cspace::leaf_blueprint())?;
            self.node = Some((prefix, depth, slot, false));
        }
        let (_, _, slot, installed) = self.node.expect("node transaction");
        if !installed {
            crate::root_cspace::install_node(sel4::cap::CNode::from_bits(slot as _), prefix, depth)
                .map_err(|error| AllocError::ArenaCleanup { slot, error })?;
            self.node = Some((prefix, depth, slot, true));
        }
        // A retained node keeps its temporary capability and its emergency
        // slot until the delete succeeds, so a retry never re-installs, never
        // reuses the slot, and never frees the same object twice.
        #[cfg(slime_metadata_lifecycle)]
        if super::INJECT_NODE_DELETE.swap(false, core::sync::atomic::Ordering::Relaxed) {
            return Err(AllocError::ArenaCleanup {
                slot,
                error: sel4::Error::IllegalOperation,
            });
        }
        sel4::init_thread::slot::CNODE
            .cap()
            .absolute_cptr(sel4::CPtr::from_bits(slot as _))
            .delete()
            .map_err(|error| AllocError::ArenaCleanup { slot, error })?;
        self.slots[slot - self.base] = SlotState::Free;
        self.node = None;
        self.nodes += 1;
        Ok(())
    }

    pub const fn owned_bytes(&self) -> usize {
        self.owned_bytes
    }

    /// Durable CNodes installed into the expanded root namespace.
    pub const fn installed_nodes(&self) -> usize {
        self.nodes
    }

    /// Whether a mapping or node transaction is retained and awaiting retry.
    pub const fn pending(&self) -> bool {
        self.mapping.address.is_some() || self.node.is_some()
    }

    /// Bytes a retained transaction still owns in emergency slots until its
    /// retry transfers or frees them. They belong to no other owner and are
    /// never reassigned meanwhile.
    ///
    /// Slot zero is excluded: it holds the permanent pin that keeps the
    /// source's allocation cursor from resetting, which is ownership by
    /// design rather than a transaction awaiting retry.
    pub fn quarantined_bytes(&self) -> usize {
        self.slots
            .iter()
            .skip(1)
            .map(|state| match state {
                SlotState::Owned { bytes } => *bytes,
                _ => 0,
            })
            .sum()
    }

    pub fn remaining_bytes(&self) -> usize {
        self.source.as_ref().map_or(0, UntypedRegion::remaining)
    }
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }
    pub const fn alignment_bytes(&self) -> usize {
        self.alignment_bytes
    }

    /// Emergency slots the bootstrap reserve holds, and the largest number one
    /// metadata or CNode transaction can spend before it must publish.
    pub const fn reserve_slots() -> usize {
        EMERGENCY_SLOTS
    }
    pub const fn transaction_slots() -> usize {
        MAX_TRANSACTION_OBJECTS
    }

    /// Free emergency slots, for reporting which resource a refusal ran out
    /// of rather than inferring it.
    #[cfg(slime_bootstrap_boundaries)]
    pub fn free_reserve_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|state| **state == SlotState::Free)
            .count()
    }

    /// Withhold the source tail so growth must refuse for want of RAM. No
    /// object is retyped, so restoring the cursor restores exact ownership.
    #[cfg(slime_bootstrap_boundaries)]
    pub fn hold_remaining(&mut self) -> usize {
        let remaining = self.remaining_bytes();
        if let Some(source) = self.source.as_mut() {
            source.watermark = source.capacity();
        }
        remaining
    }

    #[cfg(slime_bootstrap_boundaries)]
    pub fn restore_remaining(&mut self, remaining: usize) {
        if let Some(source) = self.source.as_mut() {
            source.watermark = source.capacity() - remaining;
        }
    }

    /// Withhold every free emergency slot so growth must refuse for want of
    /// CSlots while its RAM and metadata window are untouched.
    #[cfg(slime_bootstrap_boundaries)]
    pub fn hold_reserve_slots(&mut self) -> usize {
        let mut held = 0;
        for state in &mut self.slots {
            if *state == SlotState::Free {
                *state = SlotState::Reserved;
                held += 1;
            }
        }
        held
    }

    #[cfg(slime_bootstrap_boundaries)]
    pub fn release_reserve_slots(&mut self, held: usize) {
        let mut left = held;
        for state in &mut self.slots {
            if left == 0 {
                break;
            }
            if *state == SlotState::Reserved {
                *state = SlotState::Free;
                left -= 1;
            }
        }
    }

    /// Move a non-pin capability to an already reserved durable slot. The
    /// destination owner must retain its backing charge; failure keeps the
    /// emergency slot owned and cannot make it available to another operation.
    pub fn drain(&mut self, slot: usize, destination: usize) -> Result<(), AllocError> {
        self.drain_with(slot, destination, |source, destination| {
            let root = sel4::init_thread::slot::CNODE.cap();
            root.absolute_cptr(sel4::CPtr::from_bits(destination as _))
                .move_(&root.absolute_cptr(sel4::CPtr::from_bits(source as _)))
        })
    }

    fn drain_with(
        &mut self,
        slot: usize,
        destination: usize,
        mut move_cap: impl FnMut(usize, usize) -> Result<(), sel4::Error>,
    ) -> Result<(), AllocError> {
        let index = slot
            .checked_sub(self.base)
            .filter(|index| *index > 0 && *index < EMERGENCY_SLOTS)
            .ok_or(AllocError::NoKernelUntyped)?;
        if !matches!(self.slots[index], SlotState::Owned { .. })
            || (self.base..self.base + EMERGENCY_SLOTS).contains(&destination)
        {
            return Err(AllocError::NoKernelUntyped);
        }
        move_cap(slot, destination).map_err(|error| AllocError::ArenaCleanup { slot, error })?;
        self.slots[index] = SlotState::Free;
        if self.mapping.frame == Some(slot) {
            self.mapping.frame = Some(destination);
        }
        for table in &mut self.mapping.tables {
            if *table == Some(slot) {
                *table = Some(destination);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
impl Infrastructure {
    /// Pin a source without retyping, for host tests that adopt extents.
    pub(super) fn pin_for_test(&mut self, source: UntypedRegion) {
        self.owned_bytes = source.capacity();
        self.source = Some(source);
        self.pinned = true;
    }
}

#[cfg(test)]
mod tests {
    use super::super::GRANULE_BYTES;
    use super::*;

    #[test]
    fn mapping_handoff_refusal_preserves_ownership_until_recorded() {
        let mut infra = Infrastructure::new();
        assert!(
            infra
                .finish_mapping(|_| panic!("unmapped handoff"))
                .is_err()
        );
        infra.mapping = MappingTransaction {
            address: Some(METADATA_BASE),
            frame: Some(101),
            tables: [Some(102); sel4::vspace_levels::NUM_LEVELS],
            mapped: true,
        };
        assert!(
            infra
                .finish_mapping(|_| Err(AllocError::NoKernelUntyped))
                .is_err()
        );
        assert!(infra.mapping.mapped);
        assert_eq!(infra.mapping.frame, Some(101));
        let mut retained = None;
        infra
            .finish_mapping(|owned| {
                retained = Some(owned);
                Ok(())
            })
            .unwrap();
        assert_eq!(retained.unwrap().frame, 101);
        assert_eq!(retained.unwrap().address, METADATA_BASE);
        assert!(!infra.mapping.mapped);
        assert_eq!(infra.mapping.address, None);
        assert!(
            infra
                .finish_mapping(|_| panic!("duplicate handoff"))
                .is_err()
        );
    }

    #[test]
    fn bootstrap_retype_and_drain_failures_retain_exact_ownership() {
        let source = UntypedRegion {
            cap: sel4::cap::Untyped::from_bits(42),
            paddr: 0x40000000,
            size_bits: 20,
            watermark: 0,
        };
        let mut failed = Infrastructure::new();
        assert!(
            failed
                .initialize_with(source, 100, |_, _, _| Err(sel4::Error::NotEnoughMemory))
                .is_err()
        );
        assert!(
            failed
                .allocate_with(
                    sel4::FrameObjectType::GRANULE.blueprint(),
                    |_, _, _| panic!("unpinned source")
                )
                .is_err()
        );
        let mut infra = Infrastructure::new();
        infra
            .initialize_with(source, 100, |_, _, _| Ok(()))
            .unwrap();
        let pin_bytes = 1 << sel4::sys::seL4_MinUntypedBits;
        let frame = sel4::FrameObjectType::GRANULE.blueprint();
        assert!(
            infra
                .allocate_with(frame, |_, _, _| Err(sel4::Error::NotEnoughMemory))
                .is_err()
        );
        assert_eq!(infra.object_bytes(), pin_bytes);
        let slot = infra.allocate_with(frame, |_, _, _| Ok(())).unwrap();
        assert_eq!(slot, 101);
        assert_eq!(infra.object_bytes(), pin_bytes + GRANULE_BYTES);
        assert_eq!(infra.alignment_bytes(), GRANULE_BYTES - pin_bytes);
        assert_eq!(
            infra.remaining_bytes() + infra.object_bytes() + infra.alignment_bytes(),
            1 << 20
        );
        assert!(
            infra
                .drain_with(slot, 200, |_, _| Err(sel4::Error::InvalidCapability))
                .is_err()
        );
        let next = infra.allocate_with(frame, |_, _, _| Ok(())).unwrap();
        assert_eq!(next, 102);
        infra.drain_with(slot, 200, |_, _| Ok(())).unwrap();
        assert!(
            infra
                .drain_with(slot, 201, |_, _| panic!("must not move twice"))
                .is_err()
        );
        assert_eq!(infra.allocate_with(frame, |_, _, _| Ok(())).unwrap(), 101);
        assert!(
            infra
                .drain_with(100, 200, |_, _| panic!("must retain pin"))
                .is_err()
        );
    }
}
