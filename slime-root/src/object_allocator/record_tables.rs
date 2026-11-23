//! The allocator's two record tables, each with one write path.
//!
//! Every figure one growth request needs from a table is kept where records
//! are written instead of counted by walking the table: owned allocation
//! descriptors, present extent records, the bytes of returned extents, the
//! lowest returned extent of each private size, the lowest vacant extent slot,
//! and each arena's extents with room in selection order. Serving a request
//! therefore costs the same however many records the tables hold.
//!
//! Neither table hands out a mutable reference to a record. `set` and
//! `update` are the only writers, and each keeps every figure in step with
//! what it wrote, so no caller can change a record without the figures
//! following it.

use core::ops::Index;
use core::ptr::NonNull;

use super::segmented::Segmented;
use super::{
    AllocError, AllocationRecord, ExtentKind, ExtentRecord, ExtentSource, MAX_TASK_ARENAS,
    MAX_TASK_EXTENTS, TaskArenaId, plan_allocation,
};

/// No next extent on a room chain.
pub(super) const NO_LINK: u32 = u32::MAX;
/// A granule, the smallest object any private extent holds.
const GRANULE_BITS: usize = 12;
/// Sizes the reuse lookup answers without a walk: every size a private growth
/// decomposes into, from one granule to one 2 MiB extent.
const REUSE_FIRST_BITS: usize = GRANULE_BITS;
const REUSE_SIZES: usize = 10;

/// Selection order on a room chain: kind (data before tables), source (common
/// before borrowed), size for an elastic arena (smallest first), then index.
/// The first entry of a chain that fits a request is therefore the extent a
/// walk of the whole table selects.
type RoomKey = (u8, u8, u8, u32);

const fn reuse_size(size_bits: usize) -> Option<usize> {
    if size_bits >= REUSE_FIRST_BITS && size_bits < REUSE_FIRST_BITS + REUSE_SIZES {
        Some(size_bits - REUSE_FIRST_BITS)
    } else {
        None
    }
}

/// `figure - removed`. A maintained figure never holds less than its records
/// do, so one that would fall below zero has left them: it stays at zero and
/// marks its table out of step, whose requests then refuse, rather than
/// wrapping in a build without overflow checks.
fn less(figure: usize, removed: usize, out_of_step: &mut bool) -> usize {
    figure.checked_sub(removed).unwrap_or_else(|| {
        *out_of_step = true;
        0
    })
}

/// Allocation descriptors, one per capability an arena owns or may own.
pub(super) struct AllocationTable {
    records: Segmented<AllocationRecord>,
    /// Records whose owner is not `u16::MAX`: arena-owned and stress-held.
    owned: usize,
    /// A write removed more than `owned` held.
    out_of_step: bool,
    /// Owned records read since the last reset, in host tests only.
    #[cfg(test)]
    reads: core::cell::Cell<usize>,
}

impl AllocationTable {
    pub const fn new() -> Self {
        Self {
            records: Segmented::new(),
            owned: 0,
            out_of_step: false,
            #[cfg(test)]
            reads: core::cell::Cell::new(0),
        }
    }

    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Records whose owner is not `u16::MAX`.
    pub const fn owned(&self) -> usize {
        self.owned
    }

    pub const fn needs_directory_page(&self) -> bool {
        self.records.needs_directory_page()
    }

    /// # Safety
    ///
    /// As for [`Segmented::add_directory_page`].
    pub unsafe fn add_directory_page(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        // SAFETY: the caller upholds the page-transfer contract this forwards.
        unsafe { self.records.add_directory_page(page) }
    }

    /// Append one page of unowned records.
    ///
    /// # Safety
    ///
    /// As for [`Segmented::append`].
    pub unsafe fn append(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        // SAFETY: the caller upholds the page-transfer contract this forwards.
        unsafe { self.records.append(page, AllocationRecord::EMPTY) }
    }

    pub fn get(&self, index: usize) -> Option<&AllocationRecord> {
        let record = self.records.get(index);
        #[cfg(test)]
        {
            if let Some(record) = record {
                self.note(record);
            }
        }
        record
    }

    #[cfg(not(test))]
    pub fn iter(&self) -> impl Iterator<Item = &AllocationRecord> {
        self.records.iter()
    }

    pub fn set(&mut self, index: usize, record: AllocationRecord) {
        let entry = self.records.get_mut(index).expect("record index");
        let before = entry.owner != u16::MAX;
        let after = record.owner != u16::MAX;
        *entry = record;
        self.owned = less(
            self.owned + usize::from(after),
            usize::from(before),
            &mut self.out_of_step,
        );
    }

    /// Whether `owned` has left the records: a write removed more than it
    /// held, or it counts more records than the table has. Descriptor
    /// funding refuses while it has.
    pub const fn out_of_step(&self) -> bool {
        self.out_of_step || self.owned > self.records.len()
    }

    pub fn update<R>(
        &mut self,
        index: usize,
        change: impl FnOnce(&mut AllocationRecord) -> R,
    ) -> R {
        let mut record = *self.records.get(index).expect("record index");
        let result = change(&mut record);
        self.set(index, record);
        result
    }
}

#[cfg(test)]
impl AllocationTable {
    pub fn provision_host(&mut self, entries: usize, empty: AllocationRecord) {
        assert_eq!(empty.owner, u16::MAX, "new allocation records are unowned");
        self.records.provision_host(entries, empty);
    }

    pub fn iter(&self) -> impl Iterator<Item = &AllocationRecord> {
        self.records.iter().inspect(|record| self.note(record))
    }

    fn note(&self, record: &AllocationRecord) {
        if record.owner != u16::MAX {
            self.reads.set(self.reads.get() + 1);
        }
    }

    pub fn reads(&self) -> usize {
        self.reads.get()
    }

    pub fn set_reads(&self, reads: usize) {
        self.reads.set(reads);
    }

    /// The owned count by walking every record, without counting the reads.
    pub fn recount_owned(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.owner != u16::MAX)
            .count()
    }

    /// Make the owned count disagree with the records, for the drift test.
    pub fn drift_for_test(&mut self) {
        self.owned += 1;
    }

    /// Put the owned count at zero while owned records remain.
    pub fn drift_short_for_test(&mut self) {
        self.owned = 0;
    }
}

impl Index<usize> for AllocationTable {
    type Output = AllocationRecord;

    fn index(&self, index: usize) -> &AllocationRecord {
        self.get(index).expect("record index")
    }
}

/// A maintained figure a host test can make disagree with its records.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) enum ExtentDrift {
    Present,
    FreeBytes,
    Reuse {
        size_bits: usize,
    },
    ReuseCursor {
        size_bits: usize,
    },
    Vacancy,
    RoomChain {
        arena: usize,
    },
    /// A figure at zero while its records still hold some.
    PresentShort,
    FreeBytesShort,
    ReuseShort {
        size_bits: usize,
    },
}

/// Extent records, one per untyped region an arena, a reservation or the
/// common pool holds.
pub(super) struct ExtentTable {
    records: Segmented<Option<ExtentRecord>>,
    /// Slots holding a record.
    present: usize,
    /// Bytes of every common-free record.
    free_bytes: usize,
    /// Common-free records of each reuse size.
    free_count: [u32; REUSE_SIZES],
    /// No common-free record of that reuse size sits below this index.
    reuse_from: [usize; REUSE_SIZES],
    /// No vacant slot sits below this index.
    vacant_from: usize,
    /// Each arena's private extents with room for a granule, in [`RoomKey`]
    /// order, linked through [`ExtentRecord::link`].
    room_head: [u32; MAX_TASK_ARENAS],
    room_len: [u32; MAX_TASK_ARENAS],
    /// Arenas whose backing arrives on demand in mixed sizes, which select
    /// best fit by extent size rather than first fit by index.
    elastic: [bool; MAX_TASK_ARENAS],
    /// A write removed more than a figure held.
    out_of_step: bool,
    /// Present records read since the last reset, in host tests only.
    #[cfg(test)]
    reads: core::cell::Cell<usize>,
}

impl ExtentTable {
    pub const fn new() -> Self {
        Self {
            records: Segmented::new(),
            present: 0,
            free_bytes: 0,
            free_count: [0; REUSE_SIZES],
            reuse_from: [0; REUSE_SIZES],
            vacant_from: 0,
            room_head: [NO_LINK; MAX_TASK_ARENAS],
            room_len: [0; MAX_TASK_ARENAS],
            elastic: [false; MAX_TASK_ARENAS],
            out_of_step: false,
            #[cfg(test)]
            reads: core::cell::Cell::new(0),
        }
    }

    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Slots holding a record.
    pub const fn present(&self) -> usize {
        self.present
    }

    /// Bytes of every common-free record.
    pub const fn free_bytes(&self) -> usize {
        self.free_bytes
    }

    /// Whether a figure has left the records: a write removed more than it
    /// held, or `present` counts more records than the table has. Selection
    /// and new extent records refuse while one has.
    pub const fn out_of_step(&self) -> bool {
        self.out_of_step || self.present > self.records.len()
    }

    pub const fn needs_directory_page(&self) -> bool {
        self.records.needs_directory_page()
    }

    /// # Safety
    ///
    /// As for [`Segmented::add_directory_page`].
    pub unsafe fn add_directory_page(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        // SAFETY: the caller upholds the page-transfer contract this forwards.
        unsafe { self.records.add_directory_page(page) }
    }

    /// Append one page of vacant slots.
    ///
    /// # Safety
    ///
    /// As for [`Segmented::append`].
    pub unsafe fn append(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        // SAFETY: the caller upholds the page-transfer contract this forwards.
        unsafe { self.records.append(page, None) }
    }

    pub fn get(&self, index: usize) -> Option<&Option<ExtentRecord>> {
        let entry = self.records.get(index);
        #[cfg(test)]
        {
            if let Some(entry) = entry {
                self.note(entry);
            }
        }
        entry
    }

    #[cfg(not(test))]
    pub fn iter(&self) -> impl Iterator<Item = &Option<ExtentRecord>> {
        self.records.iter()
    }

    /// Replace one slot, keeping every figure in step.
    pub fn set(&mut self, index: usize, entry: Option<ExtentRecord>) {
        self.commit(index, entry);
    }

    /// Change one present record. Panics when the slot is vacant: every
    /// caller names a record it has just selected or provisioned.
    pub fn update<R>(&mut self, index: usize, change: impl FnOnce(&mut ExtentRecord) -> R) -> R {
        self.update_present(index, change).expect("extent record")
    }

    /// Change one record if the slot holds one.
    pub fn update_present<R>(
        &mut self,
        index: usize,
        change: impl FnOnce(&mut ExtentRecord) -> R,
    ) -> Option<R> {
        let mut record = (*self.records.get(index)?)?;
        let result = change(&mut record);
        self.commit(index, Some(record));
        Some(result)
    }

    /// The lowest common-free record of exactly `size_bits`.
    pub fn reusable(&mut self, size_bits: usize) -> Option<usize> {
        let Some(size) = reuse_size(size_bits) else {
            return self.iter().position(|entry| {
                entry.is_some_and(|extent| extent.is_common_free() && extent.size_bits == size_bits)
            });
        };
        if self.free_count[size] == 0 {
            return None;
        }
        let from = self.reuse_from[size];
        #[cfg_attr(test, allow(unused_mut))]
        let mut found =
            (from..self.records.len()).find(|index| self.reusable_at(*index, size_bits));
        if found.is_none() {
            // The count says one exists below the cursor, which the cursor
            // rules out: a figure out of step with its records.
            #[cfg(test)]
            panic!("recount: no returned extent of {size_bits} bits at or above {from}");
            #[cfg(not(test))]
            {
                found = (0..from).find(|index| self.reusable_at(*index, size_bits));
            }
        }
        if let Some(index) = found {
            self.reuse_from[size] = index;
        }
        found
    }

    fn reusable_at(&self, index: usize, size_bits: usize) -> bool {
        self.read(index)
            .is_some_and(|extent| extent.is_common_free() && extent.size_bits == size_bits)
    }

    /// The lowest vacant slot.
    pub fn first_vacancy(&mut self) -> Option<usize> {
        if self.present == self.records.len() {
            return None;
        }
        let from = self.vacant_from;
        #[cfg_attr(test, allow(unused_mut))]
        let mut found = (from..self.records.len()).find(|index| self.vacant_at(*index));
        if found.is_none() {
            #[cfg(test)]
            panic!("recount: no vacant extent slot at or above {from}");
            #[cfg(not(test))]
            {
                found = (0..from).find(|index| self.vacant_at(*index));
            }
        }
        if let Some(index) = found {
            self.vacant_from = index;
        }
        found
    }

    fn vacant_at(&self, index: usize) -> bool {
        self.get(index).is_some_and(Option::is_none)
    }

    pub const fn is_elastic(&self, arena: usize) -> bool {
        self.elastic[arena]
    }

    /// Switch one arena between first fit and best fit, reordering its chain.
    pub fn set_elastic(&mut self, arena: usize, elastic: bool) {
        if self.elastic[arena] == elastic {
            return;
        }
        self.elastic[arena] = elastic;
        self.room_head[arena] = NO_LINK;
        self.room_len[arena] = 0;
        for index in 0..self.records.len() {
            let Some(record) = self.read(index) else {
                continue;
            };
            if let Some((owner, key)) = self.room_key(index, &record)
                && owner == arena
            {
                self.insert(owner, index, key);
            }
        }
    }

    /// Forget one arena slot's selection state before the slot is reused.
    ///
    /// Every extent an arena held has left its chain by the time the arena is
    /// released, because settling a record removes it through the write path.
    pub fn reset_arena(&mut self, arena: usize) {
        #[cfg(test)]
        assert!(
            self.room_head[arena] == NO_LINK && self.room_len[arena] == 0,
            "recount: arena {arena} released with extents on its room chain"
        );
        self.room_head[arena] = NO_LINK;
        self.room_len[arena] = 0;
        self.elastic[arena] = false;
    }

    /// The extent the arena's room chain selects for one private object.
    ///
    /// Equal to the walk's answer: the chain holds every extent of the arena
    /// with room for a granule, so every candidate for a larger object too,
    /// in the order the walk prefers. The walk is bounded by the chain's
    /// recorded length and by the table's capacity, and a link that names no
    /// extent with room of this arena, or breaks the order, refuses the
    /// request rather than mapping from what it names. A table whose figures
    /// are out of step refuses the same way.
    pub fn room_select(
        &self,
        id: TaskArenaId,
        kind: ExtentKind,
        size_bits: usize,
        source: ExtentSource,
    ) -> Result<(usize, usize), AllocError> {
        let broken = AllocError::ArenaTableFull {
            limit: MAX_TASK_EXTENTS,
        };
        if self.out_of_step() {
            return Err(broken);
        }
        let too_small = AllocError::ArenaTooSmall {
            size_bits,
            required: 1usize << size_bits,
        };
        let arena = id.index();
        let wanted = (
            room_rank(kind).ok_or(too_small)?,
            u8::from(!matches!(source, ExtentSource::Common)),
        );
        let length = (self.room_len[arena] as usize).min(self.records.len());
        let mut current = self.room_head[arena];
        let mut previous: Option<RoomKey> = None;
        for _ in 0..length {
            if current == NO_LINK {
                return Err(broken);
            }
            let index = current as usize;
            let record = self.read(index).ok_or(broken)?;
            let (owner, key) = self.room_key(index, &record).ok_or(broken)?;
            if owner != arena || !record.belongs_to(id) || previous.is_some_and(|last| last >= key)
            {
                return Err(broken);
            }
            previous = Some(key);
            if (key.0, key.1) > wanted {
                return Err(too_small);
            }
            if (key.0, key.1) == wanted
                && source_matches(&record, source)
                && let Some((_, watermark)) =
                    plan_allocation(record.watermark, 1usize << record.size_bits, size_bits)
            {
                return Ok((index, watermark));
            }
            current = record.link;
        }
        if current != NO_LINK {
            return Err(broken);
        }
        Err(too_small)
    }

    fn commit(&mut self, index: usize, mut after: Option<ExtentRecord>) {
        let before = *self.records.get(index).expect("record index");
        self.present = less(
            self.present + usize::from(after.is_some()),
            usize::from(before.is_some()),
            &mut self.out_of_step,
        );
        if after.is_none() {
            self.vacant_from = self.vacant_from.min(index);
        }
        if let Some(record) = before.filter(ExtentRecord::is_common_free) {
            self.free_bytes = less(
                self.free_bytes,
                1usize << record.size_bits,
                &mut self.out_of_step,
            );
            if let Some(size) = reuse_size(record.size_bits) {
                // At most the count it replaces, so it fits the u32 it came from.
                self.free_count[size] =
                    less(self.free_count[size] as usize, 1, &mut self.out_of_step) as u32;
            }
        }
        if let Some(record) = after.filter(ExtentRecord::is_common_free) {
            self.free_bytes += 1usize << record.size_bits;
            if let Some(size) = reuse_size(record.size_bits) {
                self.free_count[size] += 1;
                self.reuse_from[size] = self.reuse_from[size].min(index);
            }
        }
        let old = before.and_then(|record| self.room_key(index, &record));
        let new = after.and_then(|record| self.room_key(index, &record));
        if old.is_some() && old == new {
            if let (Some(before), Some(after)) = (before, after.as_mut()) {
                after.link = before.link;
            }
            *self.records.get_mut(index).expect("record index") = after;
            return;
        }
        if let Some((owner, _)) = old {
            self.unlink(owner, index);
        }
        if let Some(after) = after.as_mut() {
            after.link = NO_LINK;
        }
        *self.records.get_mut(index).expect("record index") = after;
        if let Some((owner, key)) = new {
            self.insert(owner, index, key);
        }
    }

    /// Where `record` sits on its arena's room chain, or `None` off every chain.
    fn room_key(&self, index: usize, record: &ExtentRecord) -> Option<(usize, RoomKey)> {
        let rank = room_rank(record.kind)?;
        let owner = record.owner as usize;
        if !record.active
            || record.revoked
            || record.split
            || owner >= MAX_TASK_ARENAS
            || plan_allocation(record.watermark, 1usize << record.size_bits, GRANULE_BITS).is_none()
        {
            return None;
        }
        let size = if self.elastic[owner] {
            record.size_bits as u8
        } else {
            0
        };
        Some((
            owner,
            (rank, u8::from(record.is_borrowed()), size, index as u32),
        ))
    }

    fn insert(&mut self, arena: usize, index: usize, key: RoomKey) {
        let mut previous = NO_LINK;
        let mut current = self.room_head[arena];
        for _ in 0..self.room_len[arena] {
            if current == NO_LINK {
                break;
            }
            let Some(record) = self.read(current as usize) else {
                break;
            };
            match self.room_key(current as usize, &record) {
                Some((owner, existing)) if owner == arena && existing < key => {}
                _ => break,
            }
            previous = current;
            current = record.link;
        }
        self.set_link(index, current);
        if previous == NO_LINK {
            self.room_head[arena] = index as u32;
        } else {
            self.set_link(previous as usize, index as u32);
        }
        self.room_len[arena] += 1;
    }

    fn unlink(&mut self, arena: usize, index: usize) {
        let mut previous = NO_LINK;
        let mut current = self.room_head[arena];
        for _ in 0..self.room_len[arena] {
            if current == NO_LINK {
                break;
            }
            let Some(record) = self.read(current as usize) else {
                break;
            };
            if current as usize == index {
                if previous == NO_LINK {
                    self.room_head[arena] = record.link;
                } else {
                    self.set_link(previous as usize, record.link);
                }
                // The loop has run, so `room_len` is at least one here.
                self.room_len[arena] -= 1;
                return;
            }
            previous = current;
            current = record.link;
        }
        #[cfg(test)]
        panic!("recount: extent {index} was not on arena {arena}'s room chain");
    }

    fn set_link(&mut self, index: usize, link: u32) {
        if let Some(Some(record)) = self.records.get_mut(index) {
            record.link = link;
        }
    }

    /// One present record, counted as read.
    fn read(&self, index: usize) -> Option<ExtentRecord> {
        *self.get(index)?
    }
}

#[cfg(test)]
impl ExtentTable {
    pub fn provision_host(&mut self, entries: usize, empty: Option<ExtentRecord>) {
        assert!(empty.is_none(), "new extent slots are vacant");
        self.records.provision_host(entries, empty);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Option<ExtentRecord>> {
        self.records.iter().inspect(|entry| self.note(entry))
    }

    fn note(&self, entry: &Option<ExtentRecord>) {
        if entry.is_some() {
            self.reads.set(self.reads.get() + 1);
        }
    }

    pub fn reads(&self) -> usize {
        self.reads.get()
    }

    pub fn set_reads(&self, reads: usize) {
        self.reads.set(reads);
    }

    /// Present records by walking every slot, without counting the reads.
    pub fn recount_present(&self) -> usize {
        self.records.iter().flatten().count()
    }

    /// Common-free bytes by walking every slot, without counting the reads.
    pub fn recount_free_bytes(&self) -> usize {
        self.records
            .iter()
            .flatten()
            .filter(|extent| extent.is_common_free())
            .map(|extent| 1usize << extent.size_bits)
            .sum()
    }

    /// The lowest common-free record of `size_bits`, by walking.
    pub fn walk_reusable(&self, size_bits: usize) -> Option<usize> {
        self.records.iter().position(|entry| {
            entry.is_some_and(|extent| extent.is_common_free() && extent.size_bits == size_bits)
        })
    }

    /// The lowest vacant slot, by walking.
    pub fn walk_vacancy(&self) -> Option<usize> {
        self.records.iter().position(Option::is_none)
    }

    /// Whether `arena`'s chain holds exactly its extents with room, in order.
    pub fn room_chain_sound(&self, arena: usize) -> bool {
        let mut expected = alloc::vec::Vec::new();
        for (index, entry) in self.records.iter().enumerate() {
            if let Some(record) = entry
                && let Some((owner, key)) = self.room_key(index, record)
                && owner == arena
            {
                expected.push((key, index as u32));
            }
        }
        expected.sort_unstable();
        let mut current = self.room_head[arena];
        for (_, index) in &expected {
            if current != *index {
                return false;
            }
            current = self
                .records
                .get(current as usize)
                .and_then(|entry| entry.map(|record| record.link))
                .unwrap_or(NO_LINK);
        }
        current == NO_LINK && self.room_len[arena] as usize == expected.len()
    }

    pub fn drift_for_test(&mut self, drift: ExtentDrift) {
        match drift {
            ExtentDrift::Present => self.present += 1,
            ExtentDrift::FreeBytes => self.free_bytes += 1usize << GRANULE_BITS,
            ExtentDrift::Reuse { size_bits } => {
                let size = reuse_size(size_bits).expect("reuse size");
                self.free_count[size] += 1;
            }
            ExtentDrift::ReuseCursor { size_bits } => {
                let size = reuse_size(size_bits).expect("reuse size");
                self.reuse_from[size] = self.records.len();
            }
            ExtentDrift::Vacancy => {
                let lowest = self.walk_vacancy().expect("a vacant slot");
                self.vacant_from = lowest + 1;
            }
            ExtentDrift::RoomChain { arena } => {
                let head = self.room_head[arena];
                if head != NO_LINK {
                    self.room_head[arena] = self
                        .records
                        .get(head as usize)
                        .and_then(|entry| entry.map(|record| record.link))
                        .unwrap_or(NO_LINK);
                    self.room_len[arena] -= 1;
                }
            }
            ExtentDrift::PresentShort => self.present = 0,
            ExtentDrift::FreeBytesShort => self.free_bytes = 0,
            ExtentDrift::ReuseShort { size_bits } => {
                let size = reuse_size(size_bits).expect("reuse size");
                self.free_count[size] = 0;
            }
        }
    }

    /// Point one arena's chain head, or one record's link, anywhere at all.
    pub fn set_room_head_for_test(&mut self, arena: usize, head: u32) {
        self.room_head[arena] = head;
    }

    pub fn set_room_link_for_test(&mut self, index: usize, link: u32) {
        self.set_link(index, link);
    }

    pub fn room_len_for_test(&self, arena: usize) -> u32 {
        self.room_len[arena]
    }
}

impl Index<usize> for ExtentTable {
    type Output = Option<ExtentRecord>;

    fn index(&self, index: usize) -> &Option<ExtentRecord> {
        self.get(index).expect("record index")
    }
}

pub(super) const fn room_rank(kind: ExtentKind) -> Option<u8> {
    match kind {
        ExtentKind::PrivateData => Some(0),
        ExtentKind::PrivateTables => Some(1),
        _ => None,
    }
}

fn source_matches(record: &ExtentRecord, source: ExtentSource) -> bool {
    match source {
        ExtentSource::Common => !record.is_borrowed(),
        ExtentSource::Guaranteed(id) => {
            record.is_borrowed() && record.owned_by_reservation(id.index())
        }
    }
}
