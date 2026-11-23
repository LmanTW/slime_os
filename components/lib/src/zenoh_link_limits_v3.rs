//! The configuration of a Zenoh Profile 0 link under `contracts/zenoh-link-limits/v3`: a version 1 configuration, the runs of
//! version 2 and the subscriptions this side of the session declares. This module is that arithmetic in Rust, and the one
//! configuration the Zenoh service builds its session from.
//!
//! [`LinkLimits`] wraps a [`LaneLimits`], so the runs keep the figures of version 2. Each local subscription beyond the first adds
//! one key slot to the stack. `scripts/lib/zenoh_link_v3_reader_exam.py` judges what the test prints against the contract.

use crate::zenoh_profile0::lane_limits::{self, LaneLimits};
use crate::zenoh_profile0::limits::{DEMO, Limits, LimitsError, Mode, SLOT_OVERHEAD_BYTES};
use crate::zenoh_profile0::session::Params;

/// The most local subscriptions a link may declare: the width of a subscriber id's low half.
pub const MAX_LOCAL_SUBSCRIPTIONS: usize = 65_535;

/// A link configuration, the runs its heap holds and the subscriptions this side declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkLimits {
    pub lanes: LaneLimits,
    /// 1 to [`MAX_LOCAL_SUBSCRIPTIONS`] for both modes.
    pub local_subscriptions: usize,
}

impl LinkLimits {
    /// The stack the local subscriptions beyond the first add: one key slot for each.
    pub const fn local_bytes(&self) -> u64 {
        let extra = self.local_subscriptions.saturating_sub(1) as u64;
        extra * (self.lanes.limits.key_bytes as u64 + SLOT_OVERHEAD_BYTES)
    }

    /// The memory the owning component declares for the link's fixed storage.
    pub const fn required_stack(&self) -> u64 {
        self.lanes.required_stack() + self.local_bytes()
    }

    /// Whether the declaration is consistent with the memory it also declares. This is the version 3 contract's `configOk`,
    /// written again. The subscription count is judged before any sum is made from it.
    pub fn check(&self) -> Result<(), LimitsError> {
        if self.local_subscriptions < 1 || self.local_subscriptions > MAX_LOCAL_SUBSCRIPTIONS {
            return Err(LimitsError::Count);
        }
        // The lanes check reads the stack of the lanes alone, so it runs on a configuration that declares the stack it needs
        // beyond the local subscriptions, and the stack is judged here against the full figure.
        let mut lanes = self.lanes;
        lanes.limits.stack_bytes = lanes.limits.stack_bytes.saturating_sub(self.local_bytes());
        lanes.check()?;
        if self.lanes.limits.stack_bytes < self.required_stack() {
            return Err(LimitsError::Stack);
        }
        Ok(())
    }

    /// The session parameters the configuration describes.
    pub fn params(&self) -> Params {
        Params {
            local: self.local_subscriptions,
            ..Params::from_limits(&self.lanes.limits)
        }
    }
}

/// The configuration the Zenoh service builds its link and its session from: a fixed link of the framed 514 bytes, with the
/// 12-byte samples of its holders, 2 keys, 2 subscribers of the peer, 3 subscriptions of its own and no run.
pub const SERVICE: LinkLimits = LinkLimits {
    lanes: lane_limits::fixed(Limits {
        name: "service",
        mode: Mode::Fixed,
        batch_bytes: 514,
        payload_bytes: 12,
        max_keys: 2,
        max_subscribers: 2,
        outstanding_samples: 4,
        stack_bytes: 32_768,
        ..DEMO
    }),
    local_subscriptions: 3,
};

// The exam's test sits at the top of this module, so its name is `zenoh_link_limits_v3::the_reader_exam`, the one the judge pins.
#[cfg(test)]
include!("zenoh_link_limits_v3_tests.rs");
