//! Slot tables: the key aliases and the subscribers a session holds.
//!
//! A table is `N` slots, each the contract's `SLOT_OVERHEAD_BYTES` of bookkeeping and room for a key of
//! `K` bytes, so it occupies `table_bytes(N, K)` and `size_of` reports exactly that. A slot is found by
//! its id with open addressing from `id % N`, so ids a peer numbers in sequence land in their own slots
//! and an operation costs one probe. A removed slot is reused and the chain behind it stays intact.

use super::limits::SLOT_OVERHEAD_BYTES;

const EMPTY: u8 = 0;
const USED: u8 = 1;
const REMOVED: u8 = 2;
/// Removed by a change that may still be rolled back: not found, and not yet reusable.
const PENDING: u8 = 3;

/// Why a slot could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// A slot already holds this id.
    Duplicate,
    /// Every slot is used.
    Full,
    /// The key is longer than a slot holds.
    KeyTooLong,
}

/// The bytes a table of `slots` slots for keys of `key_max` bytes occupies.
pub const fn table_bytes(slots: usize, key_max: usize) -> usize {
    slots * (key_max + SLOT_OVERHEAD_BYTES as usize)
}

/// What a slot records besides its key: sixteen bytes, as the contract counts them.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct Meta {
    id: u64,
    len: u16,
    state: u8,
    spare: [u8; 5],
}

const _: () = assert!(core::mem::size_of::<Meta>() == SLOT_OVERHEAD_BYTES as usize);

const VACANT: Meta = Meta {
    id: 0,
    len: 0,
    state: EMPTY,
    spare: [0; 5],
};

/// Looks a key up by the id that names it.
pub trait Keys: core::fmt::Debug {
    fn key_of(&self, id: u64) -> Option<&[u8]>;
}

/// `N` slots for keys of up to `K` bytes.
#[derive(Clone, Debug)]
pub struct SlotTable<const N: usize, const K: usize> {
    meta: [Meta; N],
    keys: [[u8; K]; N],
    used: usize,
}

impl<const N: usize, const K: usize> Default for SlotTable<N, K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const K: usize> SlotTable<N, K> {
    pub const fn new() -> Self {
        Self {
            meta: [VACANT; N],
            keys: [[0; K]; N],
            used: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.used
    }

    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }

    fn state(&self, index: usize) -> u8 {
        self.meta.get(index).map_or(EMPTY, |meta| meta.state)
    }

    /// The slot holding `id`.
    pub fn find(&self, id: u64) -> Option<usize> {
        if N == 0 {
            return None;
        }
        let start = (id % N as u64) as usize;
        for step in 0..N {
            let index = (start + step) % N;
            match self.meta.get(index) {
                Some(meta) if meta.state == EMPTY => return None,
                Some(meta) if meta.state == USED && meta.id == id => return Some(index),
                _ => {}
            }
        }
        None
    }

    /// The id and key of a used slot.
    pub fn get(&self, index: usize) -> Option<(u64, &[u8])> {
        let meta = self.meta.get(index)?;
        if meta.state != USED {
            return None;
        }
        let key = self.keys.get(index)?.get(..usize::from(meta.len))?;
        Some((meta.id, key))
    }

    /// The id and key of a slot whose removal is deferred. A frame that removes a declaration reports it
    /// from here before it settles the removal.
    pub fn pending(&self, index: usize) -> Option<(u64, &[u8])> {
        let meta = self.meta.get(index)?;
        if meta.state != PENDING {
            return None;
        }
        let key = self.keys.get(index)?.get(..usize::from(meta.len))?;
        Some((meta.id, key))
    }

    /// The first used slot, for a table that holds one.
    pub fn first(&self) -> Option<(u64, &[u8])> {
        if self.used == 0 {
            return None;
        }
        (0..N).find_map(|index| self.get(index))
    }

    /// Takes a slot for `id` and `key`.
    pub fn insert(&mut self, id: u64, key: &[u8]) -> Result<usize, InsertError> {
        if key.len() > K {
            return Err(InsertError::KeyTooLong);
        }
        if self.find(id).is_some() {
            return Err(InsertError::Duplicate);
        }
        if self.used >= N {
            return Err(InsertError::Full);
        }
        let start = (id % N as u64) as usize;
        let index = (0..N)
            .map(|step| (start + step) % N)
            .find(|&index| !matches!(self.state(index), USED | PENDING))
            .ok_or(InsertError::Full)?;
        if let (Some(meta), Some(slot)) = (self.meta.get_mut(index), self.keys.get_mut(index)) {
            *meta = Meta {
                id,
                len: key.len() as u16,
                state: USED,
                spare: [0; 5],
            };
            slot.fill(0);
            if let Some(dst) = slot.get_mut(..key.len()) {
                dst.copy_from_slice(key);
            }
        }
        self.used += 1;
        Ok(index)
    }

    /// What a freed slot becomes: empty when no lookup can pass through it, a marker otherwise.
    fn vacated(&self, index: usize) -> u8 {
        if self.state((index + 1) % N) == EMPTY {
            EMPTY
        } else {
            REMOVED
        }
    }

    /// Frees a used slot. Later lookups still pass over it.
    pub fn remove(&mut self, index: usize) {
        let vacated = self.vacated(index);
        if let Some(meta) = self.meta.get_mut(index)
            && meta.state == USED
        {
            meta.state = vacated;
            self.used -= 1;
        }
    }

    /// The first slot a predicate accepts. A scan, for the lookups that are not by id.
    pub fn find_by(&self, accept: impl Fn(u64, &[u8]) -> bool) -> Option<usize> {
        if self.used == 0 {
            return None;
        }
        (0..N).find(|&index| self.get(index).is_some_and(|(id, key)| accept(id, key)))
    }

    /// The slot whose key is `key`. A scan, for the one lookup that is not by id.
    pub fn find_key(&self, key: &[u8]) -> Option<usize> {
        if self.used == 0 {
            return None;
        }
        (0..N).find(|&index| self.get(index).is_some_and(|(_, held)| held == key))
    }

    /// Takes a used slot out of lookups without making it reusable, so the change can be rolled back
    /// with [`restore`](Self::restore) or kept with [`settle`](Self::settle).
    pub fn defer_remove(&mut self, index: usize) {
        if let Some(meta) = self.meta.get_mut(index)
            && meta.state == USED
        {
            meta.state = PENDING;
            self.used -= 1;
        }
    }

    /// Makes a deferred removal final.
    pub fn settle(&mut self, index: usize) {
        let vacated = self.vacated(index);
        if let Some(meta) = self.meta.get_mut(index)
            && meta.state == PENDING
        {
            meta.state = vacated;
        }
    }

    /// Undoes a deferred removal.
    pub fn restore(&mut self, index: usize) {
        if let Some(meta) = self.meta.get_mut(index)
            && meta.state == PENDING
        {
            meta.state = USED;
            self.used += 1;
        }
    }

    /// Frees every slot.
    pub fn clear(&mut self) {
        self.meta.fill(VACANT);
        self.used = 0;
    }
}

impl<const N: usize, const K: usize> Keys for SlotTable<N, K> {
    fn key_of(&self, id: u64) -> Option<&[u8]> {
        self.get(self.find(id)?).map(|(_, key)| key)
    }
}

#[cfg(test)]
#[path = "tables_tests.rs"]
mod tests;
