//! Decoding for the generation-authenticated C9.2 wait-set resource.
//!
//! Maps badge bits on a waiter's one declared Notification back to source kinds
//! and the slot each source is drained from. A waiter cannot derive that map
//! itself: `slime-root` computes a signaller's badge from the *signaller's*
//! declared slot, and C9.1's timer badge is contract data independent of any
//! slot, so both facts belong to the generation rather than to the component
//! that blocks on them.
//!
//! Every guard here is load-bearing at admission rather than at dispatch: an
//! entry naming a badge with more than one bit, a kind outside the closed
//! vocabulary, a duplicate badge for one waiter, or a drain slot present on a
//! timer source is refused before a component ever waits.

use crate::sha256::Sha256;

/// The bounded wait-set state machine a component runs over this format.
///
/// In this crate rather than in `slime-rt` because `slime-rt` has no host build
/// — `sel4-alloca`'s inline asm is ELF-only — so tests there would be exactly
/// B23's blind spot. It also belongs beside the format whose dispatch tie rule
/// it implements.
pub mod dispatch;

include!("../generated/wait_set.rs");

pub const MAGIC: [u8; 8] = *b"SLIMEWS\0";
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_ENTRIES * ENTRY_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnknownRequiredFlags,
    BadBounds,
    BadOrder,
    UnknownKind,
    BadBadge,
    BadDrainSlot,
    SourceLimit,
}

/// What a badged wake means, and what to do about it.
///
/// A closed vocabulary rather than an open tag: a wait set dispatches on kind,
/// so an unrecognized kind is not a source it should skip but a generation it
/// cannot honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A stream ingress ring or its credit edge; drain the named endpoint.
    Stream,
    /// A call request or reply edge; drain the named endpoint.
    Call,
    /// An operation goal, feedback, result, or cancellation edge.
    Operation,
    /// A C9.1 timer expiry. Carries no payload and names no slot: the holder
    /// correlates timer ids through its own bookkeeping.
    Timer,
    /// A task this waiter supervises terminated; read the named supervision
    /// handle rather than timing out.
    Supervision,
    /// A QoS event edge — deadline, liveliness, or lifespan.
    QosEvent,
    /// A driver's completion on a device the waiter serves. Signalled by a
    /// declared peer binding, and like a timer it names no slot: the waiter
    /// reads the device state it already owns.
    Device,
    /// A hardware interrupt line the root dispatches to this waiter. Signalled
    /// by the root, and its slot is the waiter's own interrupt source, through
    /// which the waiter acknowledges the arrival after it clears the device.
    Interrupt,
}

impl SourceKind {
    /// The wire value this kind is declared as.
    pub const fn id(self) -> u32 {
        match self {
            Self::Stream => KIND_STREAM,
            Self::Call => KIND_CALL,
            Self::Operation => KIND_OPERATION,
            Self::Timer => KIND_TIMER,
            Self::Supervision => KIND_SUPERVISION,
            Self::QosEvent => KIND_QOS_EVENT,
            Self::Device => KIND_DEVICE,
            Self::Interrupt => KIND_INTERRUPT,
        }
    }

    /// The kind a wire value names, or `None` for one this build does not
    /// declare.
    pub const fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            KIND_STREAM => Self::Stream,
            KIND_CALL => Self::Call,
            KIND_OPERATION => Self::Operation,
            KIND_TIMER => Self::Timer,
            KIND_SUPERVISION => Self::Supervision,
            KIND_QOS_EVENT => Self::QosEvent,
            KIND_DEVICE => Self::Device,
            KIND_INTERRUPT => Self::Interrupt,
            _ => return None,
        })
    }

    /// Whether a source of this kind has an endpoint or handle to drain.
    ///
    /// A timer and a device completion do not. Stated as a predicate rather
    /// than left to each reader's `match`, because the resource's own validity
    /// depends on it: a timer or device entry carrying a slot, or any other kind
    /// missing one, is refused.
    pub const fn drains(self) -> bool {
        !matches!(self, Self::Timer | Self::Device)
    }
}

/// One declared wake source: which badge bit, on which Notification, means what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEntry {
    pub waiter_identity: [u8; 32],
    /// Exactly one bit. The accumulated badge word is tested against this, never
    /// compared for equality: seL4 ORs the badges of coalesced signals.
    pub badge: u64,
    /// Which of the waiter's declared Notification grants this badge arrives on.
    /// Verified against the generation's own grant table by the root, so an
    /// entry cannot attribute a badge to an object the waiter does not wait on.
    pub notification_grant_identity: u64,
    pub kind: SourceKind,
    /// The waiter's own capability slot to drain, or `None` for a timer.
    pub drain_slot: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct WaitSet<'a> {
    bytes: &'a [u8],
    entry_count: usize,
}

impl<'a> WaitSet<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if u32_at(bytes, 8)? != FORMAT_VERSION || u32_at(bytes, 12)? as usize != HEADER_BYTES {
            return Err(DecodeError::UnsupportedVersion);
        }
        if u64_at(bytes, 16)? != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        let entry_count = u32_at(bytes, 24)? as usize;
        let total_len = u32_at(bytes, 28)? as usize;
        if entry_count > MAX_ENTRIES
            || total_len != HEADER_BYTES + entry_count * ENTRY_BYTES
            || total_len != bytes.len()
        {
            return Err(DecodeError::BadBounds);
        }
        // Sorted by `(waiter_identity, badge)`, which is also the dispatch tie
        // rule: a waiter drains its ready set in ascending badge order, so the
        // sort is not merely a canonical encoding but the order the contract
        // promises. Ascending-and-distinct within one waiter therefore rejects
        // both a non-canonical resource and a duplicate badge in one test.
        let mut previous: Option<([u8; 32], u64)> = None;
        let mut run_identity = [0u8; 32];
        let mut run_sources = 0usize;
        for index in 0..entry_count {
            let entry = decode_entry(bytes, index)?;
            if entry.waiter_identity == [0; 32] {
                return Err(DecodeError::BadOrder);
            }
            if let Some((last_identity, last_badge)) = previous {
                let ordered = match entry.waiter_identity.cmp(&last_identity) {
                    core::cmp::Ordering::Greater => true,
                    core::cmp::Ordering::Equal => entry.badge > last_badge,
                    core::cmp::Ordering::Less => false,
                };
                if !ordered {
                    return Err(DecodeError::BadOrder);
                }
            }
            if entry.waiter_identity == run_identity {
                run_sources += 1;
            } else {
                run_identity = entry.waiter_identity;
                run_sources = 1;
            }
            if run_sources > MAX_SOURCES_PER_WAITER {
                return Err(DecodeError::SourceLimit);
            }
            previous = Some((entry.waiter_identity, entry.badge));
        }
        Ok(Self { bytes, entry_count })
    }

    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn entry(&self, index: usize) -> Option<SourceEntry> {
        (index < self.entry_count)
            .then(|| decode_entry(self.bytes, index).expect("validated wait-set entry"))
    }

    /// The exact encoded bytes of entry `index`.
    ///
    /// What the root serves over `WAIT_SOURCES`: the caller decodes with this
    /// same module, so re-encoding a decoded entry would introduce a second
    /// writer for one layout.
    pub fn entry_bytes(&self, index: usize) -> Option<&'a [u8]> {
        (index < self.entry_count).then(|| entry_bytes(self.bytes, index).expect("validated entry"))
    }

    /// How many sources `waiter` declares.
    pub fn source_count(&self, waiter: &[u8; 32]) -> usize {
        (0..self.entry_count)
            .filter_map(|index| self.entry(index))
            .filter(|entry| entry.waiter_identity == *waiter)
            .count()
    }

    /// `waiter`'s sources, in the contract's ascending-badge dispatch order.
    pub fn sources_for(
        &self,
        waiter: &'a [u8; 32],
    ) -> impl Iterator<Item = SourceEntry> + use<'a, '_> {
        (0..self.entry_count)
            .filter_map(move |index| self.entry(index))
            .filter(move |entry| entry.waiter_identity == *waiter)
    }
}

/// Stable identity of a waiting instance. Its own domain tag, so an identity
/// computed for a clock authority or a memory budget can never be replayed here.
pub fn waiter_identity(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"slime-wait-set-waiter-v1");
    hasher.update(&(name.len() as u16).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.finalize()
}

/// Stable identity of the generation notification grant an entry names.
///
/// Deliberately *not* `clock_authority::notification_grant_identity`, even
/// though both hash a grant name to eight bytes: an identity minted for one
/// resource must not authenticate in the other, or a timer entry's grant field
/// could be lifted verbatim into a wait-set entry that names a different
/// object's badge.
pub fn notification_grant_identity(name: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"slime-wait-set-notification-grant-v1");
    hasher.update(&(name.len() as u16).to_le_bytes());
    hasher.update(name.as_bytes());
    u64::from_le_bytes(hasher.finalize()[..8].try_into().unwrap())
}

fn entry_bytes(bytes: &[u8], index: usize) -> Result<&[u8], DecodeError> {
    let offset = HEADER_BYTES + index * ENTRY_BYTES;
    bytes
        .get(offset..offset + ENTRY_BYTES)
        .ok_or(DecodeError::Truncated)
}

fn decode_entry(bytes: &[u8], index: usize) -> Result<SourceEntry, DecodeError> {
    let entry = entry_bytes(bytes, index)?;
    if u64_at(entry, 56)? != 0 {
        return Err(DecodeError::UnknownRequiredFlags);
    }
    let badge = u64_at(entry, 32)?;
    // One bit, because a badge *is* the source's identity in the coalesced word.
    // Two bits would make one entry answer for two signallers, and zero would
    // make it answer for none — `notification_poll` already collapses a zero
    // badge to "no wake".
    if badge.count_ones() != 1 {
        return Err(DecodeError::BadBadge);
    }
    let kind = SourceKind::from_id(u32_at(entry, 48)?).ok_or(DecodeError::UnknownKind)?;
    let declared_slot = u32_at(entry, 52)?;
    // Presence must agree with the kind exactly. A timer carrying a slot claims
    // a payload C9.1 never delivers; any other kind without one names readiness
    // the waiter has nothing to act on.
    let declared = (declared_slot != DRAIN_SLOT_ABSENT).then_some(declared_slot);
    if declared.is_some() != kind.drains() {
        return Err(DecodeError::BadDrainSlot);
    }
    let drain_slot = declared;
    Ok(SourceEntry {
        waiter_identity: entry[..32].try_into().unwrap(),
        badge,
        notification_grant_identity: u64_at(entry, 40)?,
        kind,
        drain_slot,
    })
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn encoded(entries: &[[u8; ENTRY_BYTES]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        bytes.extend_from_slice(
            &(HEADER_BYTES as u32 + entries.len() as u32 * ENTRY_BYTES as u32).to_le_bytes(),
        );
        for entry in entries {
            bytes.extend_from_slice(entry);
        }
        bytes
    }

    fn entry(name: &str, badge: u64, kind: u32, slot: u32) -> [u8; ENTRY_BYTES] {
        let mut entry = [0u8; ENTRY_BYTES];
        entry[..32].copy_from_slice(&waiter_identity(name));
        entry[32..40].copy_from_slice(&badge.to_le_bytes());
        entry[40..48].copy_from_slice(&notification_grant_identity("wake").to_le_bytes());
        entry[48..52].copy_from_slice(&kind.to_le_bytes());
        entry[52..56].copy_from_slice(&slot.to_le_bytes());
        entry
    }

    /// The dispatch order the contract promises is the encoded order, so a
    /// waiter's sources arrive by ascending badge without the waiter sorting.
    #[test]
    fn sources_are_ordered_by_ascending_badge() {
        let bytes = encoded(&[
            entry("w", 1 << 1, KIND_STREAM, 3),
            entry("w", 1 << 4, KIND_TIMER, DRAIN_SLOT_ABSENT),
            entry("w", 1 << 7, KIND_SUPERVISION, 5),
        ]);
        let decoded = WaitSet::decode(&bytes).unwrap();
        let identity = waiter_identity("w");
        let badges: Vec<u64> = decoded.sources_for(&identity).map(|s| s.badge).collect();
        assert_eq!(badges, [1 << 1, 1 << 4, 1 << 7]);
        assert_eq!(decoded.source_count(&identity), 3);
        assert_eq!(decoded.source_count(&waiter_identity("other")), 0);
    }

    /// Within one waiter the encoding is strictly ascending, which is what makes
    /// a repeated badge — two sources the coalesced word could never tell
    /// apart — a decode failure rather than a silent aliasing.
    #[test]
    fn a_repeated_badge_for_one_waiter_is_refused() {
        let bytes = encoded(&[
            entry("w", 1 << 2, KIND_STREAM, 3),
            entry("w", 1 << 2, KIND_CALL, 4),
        ]);
        assert!(matches!(
            WaitSet::decode(&bytes),
            Err(DecodeError::BadOrder)
        ));
    }

    /// A badge is the source's identity in the OR-ed word, so it is exactly one
    /// bit: zero is indistinguishable from "no wake", and two would make one
    /// entry answer for two signallers.
    #[test]
    fn a_badge_names_exactly_one_bit() {
        for badge in [0, 0b11, u64::MAX] {
            let bytes = encoded(&[entry("w", badge, KIND_STREAM, 1)]);
            assert!(matches!(
                WaitSet::decode(&bytes),
                Err(DecodeError::BadBadge)
            ));
        }
    }

    /// Only a timer has nothing to drain. Both halves are refused: a timer
    /// carrying a slot claims a payload C9.1 never delivers, and any other kind
    /// without one names readiness a waiter cannot act on.
    #[test]
    fn only_a_timer_source_omits_its_drain_slot() {
        let timer_with_slot = encoded(&[entry("w", 1, KIND_TIMER, 2)]);
        assert!(matches!(
            WaitSet::decode(&timer_with_slot),
            Err(DecodeError::BadDrainSlot)
        ));
        let stream_without_slot = encoded(&[entry("w", 1, KIND_STREAM, DRAIN_SLOT_ABSENT)]);
        assert!(matches!(
            WaitSet::decode(&stream_without_slot),
            Err(DecodeError::BadDrainSlot)
        ));
        let timer = encoded(&[entry("w", 1, KIND_TIMER, DRAIN_SLOT_ABSENT)]);
        let decoded = WaitSet::decode(&timer).unwrap();
        assert_eq!(decoded.entry(0).unwrap().drain_slot, None);
        assert_eq!(decoded.entry(0).unwrap().kind, SourceKind::Timer);
    }

    /// A device completion names no drain slot, like a timer, and is refused
    /// with one. A version 2 resource is refused whole.
    #[test]
    fn a_device_source_names_no_slot_and_version_two_is_refused() {
        let device = encoded(&[entry("w", 1 << 5, KIND_DEVICE, DRAIN_SLOT_ABSENT)]);
        let decoded = WaitSet::decode(&device).unwrap();
        assert_eq!(decoded.entry(0).unwrap().kind, SourceKind::Device);
        assert_eq!(decoded.entry(0).unwrap().drain_slot, None);
        assert!(matches!(
            WaitSet::decode(&encoded(&[entry("w", 1 << 5, KIND_DEVICE, 3)])),
            Err(DecodeError::BadDrainSlot)
        ));
        let mut version_two = encoded(&[entry("w", 1, KIND_STREAM, 1)]);
        version_two[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            WaitSet::decode(&version_two),
            Err(DecodeError::UnsupportedVersion)
        ));
    }

    /// An interrupt source drains its waiter's interrupt source slot, so it is
    /// refused without one.
    #[test]
    fn an_interrupt_source_names_its_slot() {
        let interrupt = encoded(&[entry("w", 1 << 3, KIND_INTERRUPT, 3)]);
        let decoded = WaitSet::decode(&interrupt).unwrap();
        assert_eq!(decoded.entry(0).unwrap().kind, SourceKind::Interrupt);
        assert_eq!(decoded.entry(0).unwrap().drain_slot, Some(3));
        assert!(matches!(
            WaitSet::decode(&encoded(&[entry(
                "w",
                1 << 3,
                KIND_INTERRUPT,
                DRAIN_SLOT_ABSENT
            )])),
            Err(DecodeError::BadDrainSlot)
        ));
    }

    /// The vocabulary is closed: an id this build does not declare is a
    /// generation it cannot honour, not a source to skip.
    #[test]
    fn an_undeclared_kind_is_refused() {
        let bytes = encoded(&[entry("w", 1, KIND_INTERRUPT + 1, 1)]);
        assert!(matches!(
            WaitSet::decode(&bytes),
            Err(DecodeError::UnknownKind)
        ));
    }

    /// The per-waiter ceiling is a decode property, so a resource declaring a
    /// tenth source for one waiter is refused before the component sizes a
    /// queue against it.
    #[test]
    fn the_per_waiter_source_ceiling_binds() {
        let mut entries = Vec::new();
        for index in 0..=MAX_SOURCES_PER_WAITER {
            entries.push(entry("w", 1 << index, KIND_STREAM, index as u32));
        }
        assert!(matches!(
            WaitSet::decode(&encoded(&entries)),
            Err(DecodeError::SourceLimit)
        ));
        let bounded = &entries[..MAX_SOURCES_PER_WAITER];
        assert_eq!(
            WaitSet::decode(&encoded(bounded)).unwrap().entry_count(),
            MAX_SOURCES_PER_WAITER
        );
    }

    /// Two waiters may each hold the ceiling: the bound is per waiter, and the
    /// run-length scan must reset at the identity boundary rather than counting
    /// the whole resource.
    #[test]
    fn the_ceiling_is_per_waiter_not_per_resource() {
        let mut entries = Vec::new();
        for name in ["a", "b"] {
            for index in 0..MAX_SOURCES_PER_WAITER {
                entries.push(entry(name, 1 << index, KIND_STREAM, index as u32));
            }
        }
        // Numerically by badge, not bytewise: the field is little-endian, so a
        // lexicographic compare would put `1 << 8` before `1 << 0` and encode a
        // resource the decoder correctly refuses.
        entries.sort_by(|left, right| {
            left[..32].cmp(&right[..32]).then_with(|| {
                let badge = |entry: &[u8; ENTRY_BYTES]| {
                    u64::from_le_bytes(entry[32..40].try_into().unwrap())
                };
                badge(left).cmp(&badge(right))
            })
        });
        let bytes = encoded(&entries);
        let decoded = WaitSet::decode(&bytes).unwrap();
        assert_eq!(
            decoded.source_count(&waiter_identity("a")),
            MAX_SOURCES_PER_WAITER
        );
        assert_eq!(
            decoded.source_count(&waiter_identity("b")),
            MAX_SOURCES_PER_WAITER
        );
    }

    /// The two grant-identity domains are disjoint, so a clock entry's grant
    /// field cannot be lifted into a wait-set entry and still authenticate.
    #[test]
    fn grant_identity_domains_do_not_collide() {
        assert_ne!(
            notification_grant_identity("wake"),
            crate::clock_authority::notification_grant_identity("wake")
        );
        assert_ne!(
            waiter_identity("w"),
            crate::clock_authority::holder_identity("w")
        );
    }
}
