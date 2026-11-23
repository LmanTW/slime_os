//! Retained ordinary prefixes and split leaves, in resource-backed storage.
//!
//! Every record keeps a planning mirror beside its live state so the capacity
//! planner can replay provisioning without copying the registry or touching
//! live ownership. A plan that runs out of records refuses; it never publishes.

use super::{UntypedRegion, segmented::Segmented};

/// Live retained-prefix records and their planning mirror.
pub(super) trait PreservedRecords {
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn get(&self, index: usize) -> Option<UntypedRegion>;
    fn set(&mut self, index: usize, region: UntypedRegion);
    fn push(&mut self, region: UntypedRegion) -> bool;
}

/// Pure-model adapter over a caller-owned array, for host planning models.
pub(super) struct SliceRecords<'a> {
    pub entries: &'a mut [Option<UntypedRegion>],
    pub len: &'a mut usize,
}

impl PreservedRecords for SliceRecords<'_> {
    fn len(&self) -> usize {
        *self.len
    }
    fn capacity(&self) -> usize {
        self.entries.len()
    }
    fn get(&self, index: usize) -> Option<UntypedRegion> {
        self.entries.get(index).copied().flatten()
    }
    fn set(&mut self, index: usize, region: UntypedRegion) {
        self.entries[index] = Some(region);
    }
    fn push(&mut self, region: UntypedRegion) -> bool {
        if *self.len >= self.entries.len() {
            return false;
        }
        self.entries[*self.len] = Some(region);
        *self.len += 1;
        true
    }
}

#[derive(Clone, Copy)]
pub(super) struct PreservedRecord {
    live: Option<UntypedRegion>,
    planned: Option<UntypedRegion>,
}

impl PreservedRecord {
    pub const EMPTY: Self = Self {
        live: None,
        planned: None,
    };
}

/// Records the root owns before any metadata page exists: one cursor anchor
/// per admitted BootInfo region, plus the prefixes its own bootstrap spends.
const BOOTSTRAP: usize = super::MAX_KERNEL_UNTYPEDS + 64;

pub(super) struct PreservedStore {
    bootstrap: [PreservedRecord; BOOTSTRAP],
    pub records: Segmented<PreservedRecord>,
    len: usize,
}

impl PreservedStore {
    pub const fn new() -> Self {
        Self {
            bootstrap: [PreservedRecord::EMPTY; BOOTSTRAP],
            records: Segmented::new(),
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub fn capacity(&self) -> usize {
        BOOTSTRAP + self.records.len()
    }
    fn record(&self, index: usize) -> Option<&PreservedRecord> {
        if index < BOOTSTRAP {
            self.bootstrap.get(index)
        } else {
            self.records.get(index - BOOTSTRAP)
        }
    }
    fn record_mut(&mut self, index: usize) -> Option<&mut PreservedRecord> {
        if index < BOOTSTRAP {
            self.bootstrap.get_mut(index)
        } else {
            self.records.get_mut(index - BOOTSTRAP)
        }
    }
    pub fn get(&self, index: usize) -> Option<UntypedRegion> {
        (index < self.len)
            .then(|| self.record(index))
            .flatten()
            .and_then(|record| record.live)
    }
    pub fn set(&mut self, index: usize, region: UntypedRegion) {
        if index < self.len
            && let Some(record) = self.record_mut(index)
        {
            record.live = Some(region);
        }
    }
    pub fn push(&mut self, region: UntypedRegion) -> bool {
        let Some(record) = self.record_mut(self.len) else {
            return false;
        };
        record.live = Some(region);
        self.len += 1;
        true
    }
    pub fn iter(&self) -> impl Iterator<Item = UntypedRegion> + '_ {
        (0..self.len).filter_map(|index| self.get(index))
    }
    /// Mirror every live record, then plan exclusively against the copy.
    pub fn planner(&mut self) -> PreservedPlan<'_> {
        let live = self.len;
        for index in 0..live {
            if let Some(record) = self.record_mut(index) {
                record.planned = record.live;
            }
        }
        PreservedPlan {
            bootstrap: &mut self.bootstrap,
            records: &mut self.records,
            len: live,
        }
    }
}

#[cfg(test)]
impl PreservedStore {
    pub fn provision_host(&mut self, entries: usize) {
        self.records.provision_host(entries, PreservedRecord::EMPTY);
    }
}

pub(super) struct PreservedPlan<'a> {
    bootstrap: &'a mut [PreservedRecord; BOOTSTRAP],
    records: &'a mut Segmented<PreservedRecord>,
    len: usize,
}

impl PreservedPlan<'_> {
    fn record_mut(&mut self, index: usize) -> Option<&mut PreservedRecord> {
        if index < BOOTSTRAP {
            self.bootstrap.get_mut(index)
        } else {
            self.records.get_mut(index - BOOTSTRAP)
        }
    }
}

impl PreservedRecords for PreservedPlan<'_> {
    fn len(&self) -> usize {
        self.len
    }
    fn capacity(&self) -> usize {
        BOOTSTRAP + self.records.len()
    }
    fn get(&self, index: usize) -> Option<UntypedRegion> {
        if index >= self.len {
            return None;
        }
        let record = if index < BOOTSTRAP {
            self.bootstrap.get(index)
        } else {
            self.records.get(index - BOOTSTRAP)
        };
        record.and_then(|record| record.planned)
    }
    fn set(&mut self, index: usize, region: UntypedRegion) {
        if index < self.len
            && let Some(record) = self.record_mut(index)
        {
            record.planned = Some(region);
        }
    }
    fn push(&mut self, region: UntypedRegion) -> bool {
        let len = self.len;
        let Some(record) = self.record_mut(len) else {
            return false;
        };
        record.planned = Some(region);
        self.len += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(paddr: usize) -> UntypedRegion {
        UntypedRegion {
            cap: sel4::cap::Untyped::from_bits(1),
            paddr,
            size_bits: 12,
            watermark: 0,
        }
    }

    #[test]
    fn planning_mirrors_live_records_without_publishing_them() {
        let mut store = PreservedStore::new();
        assert!(store.push(region(0x1000)));
        assert!(store.push(region(0x2000)));
        let capacity = store.capacity();
        assert!(capacity >= 2);
        let mut plan = store.planner();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.capacity(), capacity);
        assert_eq!(plan.get(1).unwrap().paddr, 0x2000);
        plan.set(1, region(0x9000));
        assert!(plan.push(region(0x3000)));
        assert_eq!(plan.get(2).unwrap().paddr, 0x3000);
        assert_eq!(store.len(), 2);
        assert_eq!(store.get(1).unwrap().paddr, 0x2000);
        assert_eq!(store.get(2), None);
        assert_eq!(store.iter().count(), 2);
        // Capacity is whole record pages, and a full store refuses publication.
        while store.push(region(0x4000)) {}
        assert_eq!(store.len(), capacity);
        assert!(!store.push(region(0x5000)));
        // A second planning session starts from live state, not the last plan.
        assert_eq!(store.planner().get(1).unwrap().paddr, 0x2000);
    }
}
