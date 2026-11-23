//! Root slot occupancy and reusable planning scratch. Each bitmap word names
//! real adjacent slots in one leaf; spare metadata never grants slot authority.

use super::{AllocError, segmented::Segmented};
use core::ops::Range;

const BITS: usize = usize::BITS as usize;
const BOOTSTRAP_WORDS: usize = (super::MAX_KERNEL_UNTYPEDS + 128).div_ceil(BITS);

#[derive(Clone, Copy)]
pub(super) struct SlotWord {
    base: usize,
    valid: usize,
    used: usize,
    issued: usize,
    planned: usize,
    #[cfg(any(slime_private_stress, slime_bootstrap_boundaries, test))]
    stress: usize,
}

impl SlotWord {
    pub const EMPTY: Self = Self {
        base: 0,
        valid: 0,
        used: 0,
        issued: 0,
        planned: 0,
        #[cfg(any(slime_private_stress, slime_bootstrap_boundaries, test))]
        stress: 0,
    };
    fn mask(&self) -> usize {
        usize::MAX >> (BITS - self.valid)
    }
}

pub(super) struct SlotPool {
    bootstrap: [SlotWord; BOOTSTRAP_WORDS],
    pub words: Segmented<SlotWord>,
    count: usize,
    total: usize,
    pub live: usize,
    initial_end: usize,
    next_word: usize,
}

impl SlotPool {
    pub const EMPTY: Self = Self {
        bootstrap: [SlotWord::EMPTY; BOOTSTRAP_WORDS],
        words: Segmented::new(),
        count: 0,
        total: 0,
        live: 0,
        initial_end: 0,
        next_word: 0,
    };
    fn word(&self, index: usize) -> &SlotWord {
        if index < BOOTSTRAP_WORDS {
            &self.bootstrap[index]
        } else {
            &self.words[index - BOOTSTRAP_WORDS]
        }
    }
    fn word_mut(&mut self, index: usize) -> &mut SlotWord {
        if index < BOOTSTRAP_WORDS {
            &mut self.bootstrap[index]
        } else {
            &mut self.words[index - BOOTSTRAP_WORDS]
        }
    }
    pub fn metadata_free(&self) -> usize {
        BOOTSTRAP_WORDS + self.words.len() - self.count
    }
    pub fn initialize(&mut self, range: Range<usize>) -> Result<(), AllocError> {
        if range.start >= range.end || self.count != 0 {
            return Err(AllocError::SlotsExhausted { allocated: 0 });
        }
        self.initial_end = range.end;
        let end = range
            .end
            .min(range.start.saturating_add(BOOTSTRAP_WORDS * BITS));
        self.admit(range.start..end)
    }
    pub fn unadmitted_initial(&self) -> Range<usize> {
        let start = if self.count == 0 {
            self.initial_end
        } else {
            let word = self.word(self.count - 1);
            word.base + word.valid
        };
        start..self.initial_end
    }
    pub fn admit(&mut self, range: Range<usize>) -> Result<(), AllocError> {
        let len = range
            .end
            .checked_sub(range.start)
            .ok_or(AllocError::NoKernelUntyped)?;
        let words = len.div_ceil(BITS);
        if words > self.metadata_free() {
            return Err(AllocError::SlotsExhausted {
                allocated: self.live,
            });
        }
        if range.start == usize::MAX || range.end == usize::MAX {
            return Err(AllocError::NoKernelUntyped);
        }
        for index in 0..self.count {
            let old = self.word(index);
            if range.start < old.base + old.valid && old.base < range.end {
                return Err(AllocError::NoKernelUntyped);
            }
        }
        let total = self
            .total
            .checked_add(len)
            .ok_or(AllocError::NoKernelUntyped)?;
        for base in (range.start..range.end).step_by(BITS) {
            *self.word_mut(self.count) = SlotWord {
                base,
                valid: (range.end - base).min(BITS),
                ..SlotWord::EMPTY
            };
            self.count += 1;
        }
        self.total = total;
        Ok(())
    }
    pub fn planner(&mut self) -> SlotPlan<'_> {
        for index in 0..self.count {
            let word = self.word_mut(index);
            word.planned = word.used;
        }
        SlotPlan {
            pool: self,
            next_word: 0,
        }
    }
    pub const fn free(&self) -> usize {
        self.total - self.live
    }
    pub const fn remaining(&self) -> usize {
        self.free()
    }
    pub fn allocate(&mut self, allocated: usize) -> Result<(usize, bool), AllocError> {
        for index in self.next_word..self.count {
            let word = self.word_mut(index);
            let free = !word.used & word.mask();
            if free == 0 {
                continue;
            }
            let bit = free.trailing_zeros() as usize;
            let mask = 1usize << bit;
            let reused = word.issued & mask != 0;
            word.used |= mask;
            word.issued |= mask;
            let address = word.base + bit;
            self.next_word = index;
            self.live += 1;
            return Ok((address, reused));
        }
        Err(AllocError::SlotsExhausted { allocated })
    }
    /// The word holding `slot`, by binary search.
    ///
    /// Words are admitted in increasing base order — the initial namespace,
    /// then each expanded leaf — so a scan is unnecessary, and with the
    /// initial namespace retired a scan would walk every word of it before
    /// reaching the live ones on every release.
    fn locate(&self, slot: usize) -> Option<(usize, usize)> {
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let index = low + (high - low) / 2;
            let word = self.word(index);
            if slot < word.base {
                high = index;
            } else if slot - word.base < word.valid {
                return Some((index, slot - word.base));
            } else {
                low = index + 1;
            }
        }
        None
    }
    pub fn release(&mut self, slot: usize) -> bool {
        let Some((index, bit)) = self.locate(slot) else {
            return false;
        };
        let word = self.word_mut(index);
        let mask = 1usize << bit;
        if word.used & mask == 0 {
            return false;
        }
        word.used &= !mask;
        self.live -= 1;
        self.next_word = self.next_word.min(index);
        true
    }
    fn contiguous(&self, count: usize, extra: Option<usize>, planned: bool) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let mut start = 0;
        let mut run = 0;
        let mut previous = None;
        for word in self
            .bootstrap
            .iter()
            .chain(self.words.iter())
            .take(self.count)
        {
            let bitmap = if planned { word.planned } else { word.used };
            if bitmap & word.mask() == word.mask() {
                run = 0;
                previous = None;
                continue;
            }
            for bit in 0..word.valid {
                let address = word.base + bit;
                let same_leaf = previous.is_none_or(|prev: usize| {
                    address == prev + 1 && (address < 1usize << 60 || address >> 10 == prev >> 10)
                });
                if !same_leaf {
                    run = 0;
                }
                previous = Some(address);
                if bitmap & (1usize << bit) != 0 || extra == Some(address) {
                    run = 0;
                    continue;
                }
                if run == 0 {
                    start = address;
                }
                run += 1;
                if run == count {
                    return Some(start);
                }
            }
        }
        None
    }
    pub fn first_contiguous(&self, count: usize, extra: Option<usize>) -> Option<usize> {
        self.contiguous(count, extra, false)
    }
    pub fn allocate_contiguous(
        &mut self,
        count: usize,
        allocated: usize,
    ) -> Result<(usize, usize), AllocError> {
        let start = self
            .contiguous(count, None, false)
            .ok_or(AllocError::SlotsExhausted { allocated })?;
        let mut reused = 0;
        for slot in start..start + count {
            let (index, bit) = self.locate(slot).expect("contiguous slot");
            let word = self.word_mut(index);
            let mask = 1usize << bit;
            reused += usize::from(word.issued & mask != 0);
            word.used |= mask;
            word.issued |= mask;
        }
        self.live += count;
        Ok((start, reused))
    }
    /// Occupancy words the pool has admitted, bootstrap and grown together.
    pub const fn words(&self) -> usize {
        self.count
    }
    /// Permanently retire every free slot below `limit`.
    ///
    /// Retired slots stay occupied: the pool never hands them out again, so
    /// later allocation is served from leaves admitted above that boundary.
    #[cfg(slime_cspace_expanded)]
    pub fn retire_below(&mut self, limit: usize) -> usize {
        let mut retired = 0;
        for index in 0..self.count {
            let word = self.word_mut(index);
            if word.base >= limit {
                continue;
            }
            let free = !word.used & word.mask();
            word.used |= free;
            word.issued |= free;
            retired += free.count_ones() as usize;
        }
        self.live += retired;
        retired
    }
    #[cfg(any(slime_private_stress, slime_bootstrap_boundaries, test))]
    pub fn reserve_stress_pressure(&mut self, leave: usize) -> usize {
        let count = self.free().saturating_sub(leave);
        let mut left = count;
        for index in 0..self.count {
            let word = self.word_mut(index);
            while left != 0 {
                let free = !word.used & word.mask();
                if free == 0 {
                    break;
                }
                let mask = 1usize << free.trailing_zeros();
                word.used |= mask;
                word.stress |= mask;
                left -= 1;
            }
        }
        self.live += count - left;
        count - left
    }
    #[cfg(any(slime_private_stress, slime_bootstrap_boundaries, test))]
    pub fn release_stress_pressure(&mut self) {
        let mut released = 0;
        for index in 0..self.count {
            let word = self.word_mut(index);
            released += word.stress.count_ones() as usize;
            word.used &= !word.stress;
            word.stress = 0;
        }
        self.live -= released;
        self.next_word = 0;
    }
}

#[cfg(test)]
impl SlotPool {
    pub fn new(range: Range<usize>) -> Result<Self, AllocError> {
        let mut pool = Self::EMPTY;
        pool.initialize(range.clone())?;
        pool.words
            .provision_host(range.len().div_ceil(BITS), SlotWord::EMPTY);
        pool.admit(pool.unadmitted_initial())?;
        Ok(pool)
    }
}

pub(super) struct SlotPlan<'a> {
    pool: &'a mut SlotPool,
    next_word: usize,
}
impl SlotPlan<'_> {
    pub fn allocate(&mut self, allocated: usize) -> Result<(usize, bool), AllocError> {
        for index in self.next_word..self.pool.count {
            let word = self.pool.word_mut(index);
            let free = !word.planned & word.mask();
            if free == 0 {
                continue;
            }
            let bit = free.trailing_zeros();
            word.planned |= 1usize << bit;
            let address = word.base + bit as usize;
            self.next_word = index;
            return Ok((address, false));
        }
        Err(AllocError::SlotsExhausted { allocated })
    }
    pub fn allocate_contiguous(
        &mut self,
        count: usize,
        allocated: usize,
    ) -> Result<(usize, usize), AllocError> {
        let start = self
            .pool
            .contiguous(count, None, true)
            .ok_or(AllocError::SlotsExhausted { allocated })?;
        for slot in start..start + count {
            let (index, bit) = self.pool.locate(slot).expect("planned slot");
            self.pool.word_mut(index).planned |= 1usize << bit;
        }
        Ok((start, 0))
    }
}
