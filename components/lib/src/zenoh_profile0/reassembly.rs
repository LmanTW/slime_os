//! Reassembly of fragmented messages into storage the component supplies.
//!
//! A heap link is built over a slice of memory the owning component provides from its own allocator;
//! this library takes no allocator of its own. [`Reassembly`] joins the slices of a run of FRAGMENTs
//! into the front of that slice, one message at a time. It owns no memory and keeps no clock: the
//! caller passes the time of each fragment, so the deadline is measured from the first fragment's
//! arrival and a continuation never refreshes it.
//!
//! Every way a run can end releases the storage, so the next message starts from empty: it completes,
//! it is refused, or it outlives its timeout. A refusal leaves the run as it was only in the sense that
//! the run is gone; the session's own sequence number is committed by the caller after a whole message
//! is accepted, never by a refused one.

use super::fragment::{Fragment, FragmentError};

/// Where a reassembly stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// More fragments are expected.
    Open,
    /// The final fragment arrived: the message is `message()` long.
    Complete(usize),
}

/// The state of one run of fragments. It holds no timeout and no limit of its own: the caller passes both, so
/// a table of runs shares them.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    /// The sequence number the next fragment must carry, while the run is open.
    next_sn: u32,
    open: bool,
    /// Whether the last fragment seen said more follow.
    more: bool,
    len: usize,
    /// When the first fragment of the open run arrived.
    started_ms: u64,
}

impl Run {
    pub const fn new() -> Self {
        Self {
            next_sn: 0,
            open: false,
            more: false,
            len: 0,
            started_ms: 0,
        }
    }

    pub const fn is_open(&self) -> bool {
        self.open
    }

    /// The bytes joined so far.
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The sequence number the next fragment must carry. It means something only while the run is open.
    pub const fn next_sn(&self) -> u32 {
        self.next_sn
    }

    /// The time after which an open run is refused, `None` while none is open.
    pub const fn deadline(&self, timeout_ms: u64) -> Option<u64> {
        if self.open {
            Some(self.started_ms.saturating_add(timeout_ms))
        } else {
            None
        }
    }

    pub fn expired(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.deadline(timeout_ms)
            .is_some_and(|deadline| now_ms > deadline)
    }

    pub fn release(&mut self) {
        self.open = false;
        self.len = 0;
        self.more = false;
    }

    /// Takes one fragment into `storage`. `expected_sn` is the number the first fragment of a run must carry;
    /// later fragments must follow their predecessor. Any refusal ends the run and frees the storage.
    pub fn accept(
        &mut self,
        fragment: &Fragment<'_>,
        storage: &mut [u8],
        expected_sn: u32,
        now_ms: u64,
        timeout_ms: u64,
        limit: usize,
    ) -> Result<Progress, FragmentError> {
        let result = self.take(fragment, storage, expected_sn, now_ms, timeout_ms, limit);
        if result.is_err() {
            self.release();
        }
        result
    }

    fn take(
        &mut self,
        fragment: &Fragment<'_>,
        storage: &mut [u8],
        expected_sn: u32,
        now_ms: u64,
        timeout_ms: u64,
        limit: usize,
    ) -> Result<Progress, FragmentError> {
        if self.open {
            if self.expired(now_ms, timeout_ms) {
                return Err(FragmentError::ReassemblyTimeout);
            }
            if !self.more {
                return Err(FragmentError::FragmentSequence);
            }
            if fragment.sn != self.next_sn {
                return Err(FragmentError::FragmentSequence);
            }
        } else {
            if fragment.sn != expected_sn {
                return Err(FragmentError::SequenceMismatch);
            }
            self.started_ms = now_ms;
        }
        let end = self
            .len
            .checked_add(fragment.data.len())
            .ok_or(FragmentError::OutOfMemory)?;
        if end > limit {
            return Err(crate::zenoh_profile0::Refusal::OverBound.into());
        }
        let slot = storage
            .get_mut(self.len..end)
            .ok_or(FragmentError::OutOfMemory)?;
        slot.copy_from_slice(fragment.data);
        self.len = end;
        self.next_sn = fragment.sn.wrapping_add(1);
        self.open = true;
        self.more = fragment.more;
        if fragment.more {
            Ok(Progress::Open)
        } else {
            Ok(Progress::Complete(self.len))
        }
    }

    /// The message of a completed run, borrowed from `storage`, and the sequence number the session expects after
    /// it. The run is released, so the storage is free for the next message once the caller is done reading.
    pub fn finish<'s>(&mut self, storage: &'s [u8]) -> Result<(&'s [u8], u32), FragmentError> {
        if !self.open || self.more {
            return Err(FragmentError::FragmentSequence);
        }
        let next = self.next_sn;
        let message = storage.get(..self.len).ok_or(FragmentError::OutOfMemory)?;
        self.release();
        Ok((message, next))
    }
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

/// One message being joined from a run of fragments.
#[derive(Clone, Copy, Debug)]
pub struct Reassembly {
    timeout_ms: u64,
    /// The declared limit on one message, so a message over it is refused though storage would hold it.
    limit: usize,
    run: Run,
}

impl Reassembly {
    /// A reassembly whose runs may take `timeout_ms` from their first fragment, and whose messages may
    /// not exceed `limit` bytes.
    pub const fn new(timeout_ms: u64, limit: usize) -> Self {
        Self {
            timeout_ms,
            limit,
            run: Run::new(),
        }
    }

    /// Whether a run is open.
    pub const fn is_open(&self) -> bool {
        self.run.is_open()
    }

    /// The bytes joined so far.
    pub const fn len(&self) -> usize {
        self.run.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.run.is_empty()
    }

    /// The sequence number the next fragment must carry, while a run is open.
    pub const fn next_sn(&self) -> Option<u32> {
        if self.run.is_open() {
            Some(self.run.next_sn())
        } else {
            None
        }
    }

    /// The time after which an open run is refused, `None` while none is open. The last fragment may
    /// arrive exactly at it; one millisecond later is refused.
    pub const fn deadline(&self) -> Option<u64> {
        self.run.deadline(self.timeout_ms)
    }

    /// Drops the open run and frees the storage for the next message.
    pub fn release(&mut self) {
        self.run.release();
    }

    /// Whether an open run has outlived its timeout at `now_ms`. The caller releases it.
    pub fn expired(&self, now_ms: u64) -> bool {
        self.run.expired(now_ms, self.timeout_ms)
    }

    /// Takes one fragment into `storage`. `expected_sn` is the session's next expected sequence number,
    /// which the first fragment of a run must carry exactly; later fragments must follow their
    /// predecessor. Any refusal ends the run and frees the storage.
    pub fn accept(
        &mut self,
        fragment: &Fragment<'_>,
        storage: &mut [u8],
        expected_sn: u32,
        now_ms: u64,
    ) -> Result<Progress, FragmentError> {
        self.run.accept(
            fragment,
            storage,
            expected_sn,
            now_ms,
            self.timeout_ms,
            self.limit,
        )
    }

    /// The message of a completed run, borrowed from `storage`, and the sequence number the session
    /// expects after it. The run is released, so the storage is free for the next message once the
    /// caller is done reading.
    pub fn finish<'s>(&mut self, storage: &'s [u8]) -> Result<(&'s [u8], u32), FragmentError> {
        self.run.finish(storage)
    }
}

#[cfg(test)]
#[path = "reassembly_tests.rs"]
mod tests;
