//! Per-region leaf-table ownership, page-backed and nonmoving.
//!
//! A private region records which 2 MiB spans of its window already hold a leaf
//! table, because that decides whether the next page may take a large frame and
//! because a failed growth keeps a table bound to the span it was mapped into.
//! That state used to be an array inside the task record, sized from the
//! compiled target's per-region page count. A policy-derived window is not
//! bounded by that row, so the bits move here: the allocator funds them from
//! the same page-backed metadata every other record lives in, and hands the
//! region a pointer that stays valid for the region's whole life.
//!
//! One record per region rather than a packed run. [`super::segmented`]
//! guarantees a record never moves and never crosses a page, which is what lets
//! a `Copy` region hold a raw pointer at all; a variable-length run would have
//! to guarantee that separately, for a saving of a few hundred bytes per task.
//! The record's width is therefore the addressing limit on a window's spans,
//! and it refuses explicitly rather than truncating.

use core::ptr::NonNull;

use super::segmented::Segmented;

/// Bits one region's span ownership fits in.
const RUN_WORDS: usize = 64;
const WORD_BITS: usize = u64::BITS as usize;

/// Spans one window may hold, which at 2 MiB a span is an 8 GiB reservation.
pub(crate) const MAX_WINDOW_SPANS: usize = RUN_WORDS * WORD_BITS;

/// One region's span-ownership record.
///
/// `free_next` overlays the free list so a returned record costs no separate
/// index storage: a record is either owned by a live region or linked into the
/// list, never both.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct LeafSpanRun {
    words: [u64; RUN_WORDS],
    free_next: u32,
    live: bool,
}

const NONE: u32 = u32::MAX;

impl LeafSpanRun {
    pub(crate) const EMPTY: Self = Self {
        words: [0; RUN_WORDS],
        free_next: NONE,
        live: false,
    };
}

/// A live region's handle on its span-ownership record.
///
/// The pointer is the record's stable address in allocator-owned storage, which
/// is mapped for the root's whole life and never relocated. Copying a region
/// copies this handle, which is correct: both copies name the same region, and
/// only the task table's canonical record is ever mutated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeafSpanBits {
    record: Option<NonNull<LeafSpanRun>>,
    index: u32,
    spans: u32,
}

impl LeafSpanBits {
    /// The handle a region with no window holds: no record, no spans.
    pub(crate) const NONE: Self = Self {
        record: None,
        index: NONE,
        spans: 0,
    };

    pub(crate) const fn spans(self) -> usize {
        self.spans as usize
    }

    pub(crate) const fn is_none(self) -> bool {
        self.record.is_none()
    }

    /// Whether `span` already owns a leaf table.
    ///
    /// Out-of-range spans answer `false` rather than panicking: a span past the
    /// window cannot hold a table, and the growth paths refuse such a page on
    /// the reservation check that owns that rule.
    pub(crate) fn get(self, span: usize) -> bool {
        let Some(record) = self.record else {
            return false;
        };
        if span >= self.spans as usize {
            return false;
        }
        // SAFETY: the record was acquired from the allocator's page-backed
        // store, which neither frees nor moves a page, and it stays owned by
        // this region until the region is reclaimed.
        let words = unsafe { &record.as_ref().words };
        words[span / WORD_BITS] & (1u64 << (span % WORD_BITS)) != 0
    }

    /// Record that `span` now owns a leaf table, answering whether it is new.
    pub(crate) fn set(&mut self, span: usize) -> bool {
        let Some(mut record) = self.record else {
            return false;
        };
        if span >= self.spans as usize {
            return false;
        }
        // SAFETY: as in `get`, and the caller holds the region exclusively.
        let words = unsafe { &mut record.as_mut().words };
        let mask = 1u64 << (span % WORD_BITS);
        let word = &mut words[span / WORD_BITS];
        if *word & mask != 0 {
            return false;
        }
        *word |= mask;
        true
    }

    /// Forget every span's table, keeping the record.
    ///
    /// Reclamation destroys the tables themselves through the task arena's
    /// revoke; this is the ownership bookkeeping that revoke cannot see.
    pub(crate) fn clear(&mut self) {
        let Some(mut record) = self.record else {
            return;
        };
        // SAFETY: as in `set`.
        unsafe { record.as_mut().words = [0; RUN_WORDS] };
    }
}

/// Page-backed span-ownership records, with returned records reused.
pub(crate) struct LeafSpanStore {
    runs: Segmented<LeafSpanRun>,
    next: usize,
    free: u32,
}

impl LeafSpanStore {
    pub(crate) const fn new() -> Self {
        Self {
            runs: Segmented::new(),
            next: 0,
            free: NONE,
        }
    }

    pub(crate) const fn capacity_needed(&self) -> bool {
        self.free == NONE
    }

    pub(crate) fn capacity(&self) -> usize {
        self.runs.len()
    }

    /// Records this store could still hand out without new backing.
    pub(crate) fn available(&self) -> usize {
        let unused = self.runs.len().saturating_sub(self.next);
        unused + usize::from(self.free != NONE)
    }

    /// Transfer one exclusively owned, page-aligned metadata page.
    ///
    /// # Safety
    ///
    /// The page must stay mapped and unreferenced by any other record table for
    /// this store's lifetime.
    pub(crate) unsafe fn append(&mut self, page: NonNull<u8>) -> Result<(), ()> {
        unsafe { self.runs.append(page, LeafSpanRun::EMPTY) }
    }

    pub(crate) fn entries_per_page() -> usize {
        Segmented::<LeafSpanRun>::entries_per_page()
    }

    /// Hand one region a cleared record covering `spans`.
    ///
    /// Returns `None` when the window needs more spans than a record addresses,
    /// or when no record is free; the caller decides which refusal that is.
    pub(crate) fn acquire(&mut self, spans: usize) -> Option<LeafSpanBits> {
        if spans == 0 || spans > MAX_WINDOW_SPANS {
            return None;
        }
        let index = if self.free != NONE {
            let index = self.free as usize;
            let record = self.runs.get_mut(index)?;
            self.free = record.free_next;
            record.free_next = NONE;
            index
        } else {
            let index = self.next;
            self.runs.get(index)?;
            self.next += 1;
            index
        };
        let record = self.runs.get_mut(index)?;
        record.words = [0; RUN_WORDS];
        record.live = true;
        let pointer = NonNull::from(record);
        Some(LeafSpanBits {
            record: Some(pointer),
            index: index as u32,
            spans: spans as u32,
        })
    }

    /// Take a region's record back for the next region.
    ///
    /// Idempotent against a handle released twice: a record that is not live is
    /// already on the free list, and linking it again would make the list a
    /// cycle that hands the same record to two regions.
    pub(crate) fn release(&mut self, bits: LeafSpanBits) {
        if bits.record.is_none() {
            return;
        }
        let index = bits.index as usize;
        let head = self.free;
        let Some(record) = self.runs.get_mut(index) else {
            return;
        };
        if !record.live {
            return;
        }
        record.words = [0; RUN_WORDS];
        record.live = false;
        record.free_next = head;
        self.free = index as u32;
    }
}

#[cfg(test)]
impl LeafSpanStore {
    pub(crate) fn provision_host(&mut self, records: usize) {
        self.runs.provision_host(records, LeafSpanRun::EMPTY);
    }
}

/// Span records for host tests, without an allocator on the stack.
///
/// The production store is a field of `ObjectAllocator`, which is far too
/// large to place on a test thread's stack; the storage itself is the same
/// page-backed table either way, so a test that is about a region's window
/// gets its record from here.
#[cfg(test)]
pub(crate) mod host {
    extern crate std;

    use super::{LeafSpanBits, LeafSpanStore};

    std::thread_local! {
        static STORE: core::cell::RefCell<LeafSpanStore> =
            core::cell::RefCell::new(LeafSpanStore::new());
    }

    pub(crate) fn bits(spans: usize) -> Option<LeafSpanBits> {
        STORE.with(|store| {
            let mut store = store.borrow_mut();
            if store.available() == 0 {
                let grown = store.capacity() + LeafSpanStore::entries_per_page();
                store.provision_host(grown);
            }
            store.acquire(spans)
        })
    }

    pub(crate) fn release(bits: LeafSpanBits) {
        STORE.with(|store| store.borrow_mut().release(bits));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(records: usize) -> LeafSpanStore {
        let mut store = LeafSpanStore::new();
        store.provision_host(records);
        store
    }

    #[test]
    fn a_span_is_owned_only_after_it_is_marked_and_only_within_the_window() {
        let mut store = store(LeafSpanStore::entries_per_page());
        let mut bits = store.acquire(130).expect("record");
        assert!(!bits.get(0));
        assert!(bits.set(0));
        assert!(!bits.set(0), "marking the same span twice is not new");
        assert!(bits.get(0));
        assert!(bits.set(129));
        assert!(bits.get(129));
        assert!(!bits.get(130), "a span past the window owns nothing");
        assert!(!bits.set(130));
        assert!(!bits.get(1));
    }

    #[test]
    fn a_released_record_is_handed_out_cleared_and_never_twice() {
        let mut store = store(LeafSpanStore::entries_per_page());
        let mut first = store.acquire(64).expect("record");
        assert!(first.set(7));
        let index = first.index;
        store.release(first);
        // A double release must not link the same record twice, or two live
        // regions would share one record.
        store.release(first);
        let second = store.acquire(64).expect("record");
        assert_eq!(
            second.index, index,
            "the returned record funds the next one"
        );
        assert!(!second.get(7), "a reused record starts owning nothing");
        let third = store.acquire(64).expect("record");
        assert_ne!(third.index, index);
    }

    #[test]
    fn a_window_wider_than_a_record_addresses_is_refused_not_truncated() {
        let mut store = store(LeafSpanStore::entries_per_page());
        assert!(store.acquire(MAX_WINDOW_SPANS).is_some());
        assert!(store.acquire(MAX_WINDOW_SPANS + 1).is_none());
        assert!(store.acquire(0).is_none());
    }

    #[test]
    fn an_exhausted_store_refuses_rather_than_reusing_a_live_record() {
        let mut store = LeafSpanStore::new();
        store.provision_host(LeafSpanStore::entries_per_page());
        let capacity = store.capacity();
        let mut live = alloc::vec::Vec::new();
        for _ in 0..capacity {
            live.push(store.acquire(1).expect("record"));
        }
        assert_eq!(store.available(), 0);
        assert!(store.acquire(1).is_none());
        store.release(live.pop().expect("live record"));
        assert_eq!(store.available(), 1);
        assert!(store.acquire(1).is_some());
    }
}
