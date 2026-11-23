//! The configuration of a Zenoh Profile 0 link that holds several reassembly runs.
//!
//! `contracts/zenoh-link-limits/v2` adds `maxRuns` to a configuration: the fragmented messages a heap link
//! holds open at once, one for each lane. This module is that arithmetic in Rust. [`Limits`] is unchanged, so
//! every version 1 configuration keeps its figures, and a [`LaneLimits`] with one run has the same stack and
//! heap as its [`Limits`].

use super::STREAM_LENGTH_BYTES;
use super::limits::{HANDSHAKE_BYTES, Limits, LimitsError, Mode};

/// The most runs a link may hold: a lane is a priority (0 to 7) and a reliability, so a stock peer has at
/// most 16 messages open.
pub const MAX_RUNS_LIMIT: usize = 16;
/// The state of one run beyond the first, held with a margin over what a slot of the session's table holds: a
/// `Run` and the `Lane` it serves.
pub const RUN_OVERHEAD_BYTES: u64 = 64;
/// The sequence counters of the lanes, charged once for a link with several runs.
pub const LANE_COUNTER_BYTES: u64 = 64;
/// The QoS unit extension a link with several runs writes after its INIT: one byte, which makes its largest
/// INIT_ACK 88 bytes and not 87.
pub const QOS_OFFER_BYTES: usize = 1;

/// A link configuration and the runs its heap holds open at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneLimits {
    pub limits: Limits,
    /// 0 for a fixed link, 1 to [`MAX_RUNS_LIMIT`] for a heap link.
    pub max_runs: usize,
}

impl LaneLimits {
    /// The lane state of a link with several runs. A count is bounded before this is called, so the
    /// product cannot overflow.
    pub const fn lane_bytes(&self) -> u64 {
        if self.max_runs > 1 {
            (self.max_runs as u64 - 1) * RUN_OVERHEAD_BYTES + LANE_COUNTER_BYTES
        } else {
            0
        }
    }

    /// The memory the owning component declares for the link's fixed storage.
    pub const fn required_stack(&self) -> u64 {
        self.limits.required_stack() + self.lane_bytes()
    }

    /// The heap a heap link needs: every queued sample notice holds a whole message until it is consumed,
    /// and one message is being reassembled for each run.
    pub const fn heap_needed(&self) -> u64 {
        (crate::zenoh_profile0::limits::NOTICES_PER_SAMPLE as u64
            * self.limits.outstanding_samples as u64
            + self.max_runs as u64)
            * self.limits.message_bytes()
    }

    /// Whether the declaration is consistent with the memory it also declares. This is the version 2
    /// contract's `configOk`, written again. The run count is judged before any sum is made from it.
    pub fn check(&self) -> Result<(), LimitsError> {
        if self.max_runs > MAX_RUNS_LIMIT {
            return Err(LimitsError::Count);
        }
        match self.limits.mode {
            Mode::Fixed if self.max_runs != 0 => return Err(LimitsError::Fixed),
            Mode::Heap if self.max_runs < 1 => return Err(LimitsError::Heap),
            _ => {}
        }
        // Version 2 needs at least the stack and heap of version 1, so a declaration the version 1 rules
        // refuse for any other reason, or for too little of either, is refused here too.
        self.limits.check()?;
        // An INIT cannot be fragmented, so the batch must carry the largest INIT_ACK the link writes, the
        // extension and the stream length included.
        if self.max_runs > 1
            && self.limits.batch_bytes < HANDSHAKE_BYTES + STREAM_LENGTH_BYTES + QOS_OFFER_BYTES
        {
            return Err(LimitsError::Batch);
        }
        if self.limits.stack_bytes < self.required_stack() {
            return Err(LimitsError::Stack);
        }
        if self.limits.mode == Mode::Heap && self.limits.heap_bytes < self.heap_needed() {
            return Err(LimitsError::Heap);
        }
        Ok(())
    }
}

/// `limits` as a fixed link, which holds no run.
pub const fn fixed(limits: Limits) -> LaneLimits {
    LaneLimits {
        limits,
        max_runs: 0,
    }
}

/// `limits` as a heap link with `max_runs` runs.
pub const fn heap(limits: Limits, max_runs: usize) -> LaneLimits {
    LaneLimits { limits, max_runs }
}

#[cfg(test)]
#[path = "lane_limits_tests.rs"]
mod tests;
