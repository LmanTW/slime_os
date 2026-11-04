//! The Zenoh service core: one session served to local holders by their grants.
//!
//! A holder's authority is a row of `contracts/zenoh-service-grants/v1`: one exact key and the rights to
//! publish and to subscribe. The core is declared with the rows, keeps one ring of samples for each holder,
//! and serves them from one session that the caller lends it on each call. It owns no link, no clock and no
//! network authority. It does not own the session, so its size is the core's alone, and the overheads in
//! the grants contract bound that size.
//!
//! A key in a request grants nothing. A publication needs a row that grants the holder the right to
//! publish that key. It reaches every holder with a subscribe row on the key, the publisher included, and
//! it is written to the peer only if the peer declared a subscriber on the key. A sample from the peer
//! reaches every holder with a subscribe row on the key. A holder that does not take never blocks another:
//! its ring keeps the newest samples, counts what it dropped and says so once.
//!
//! The core declares one subscription for each distinct subscribe key and numbers them from 1 in the order
//! the keys first appear in the rows. The session it is lent must hold no subscription of its own that the
//! core did not declare, because a sample is routed by the id of the subscription that matched. The core
//! keeps the parameters the session was declared with and refuses a session whose parameters differ. It
//! serves whole-frame samples only, so a session that reassembles fragments is refused.

#[cfg(test)]
mod behaviour;
#[cfg(test)]
pub(crate) mod exam;
mod over_link;

pub use over_link::{OverLink, Settled};

/// Every section, in the order the exam lists them. The checker looks for this test by its path.
#[cfg(test)]
#[test]
fn the_service_exam() {
    exam::run();
}

use crate::zenoh_profile0::GID_BYTES;
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::session::{Event, Outcome, Params, SessionError, SessionOf};
use slime_proto::zenoh_service_grants::{
    HOLDER_OVERHEAD_BYTES, ROW_OVERHEAD_BYTES, SERVICE_FIXED_BYTES, SLOT_OVERHEAD_BYTES,
};

/// Why the core refused a call. A refused call changes no ring and writes nothing to the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The holder is not one of the declared holders.
    UnknownHolder,
    /// The holder has no row that grants the right to publish this key.
    NotGranted,
    /// The payload is larger than a ring slot.
    TooLarge,
    /// The grants cannot be served by this core and this session.
    InvalidGrants,
    /// The session lent to the core is not the one the core was declared with.
    WrongSession,
    /// The session refused the call.
    Session(SessionError),
    /// A publication or declaration is still waiting for the link to flush it, or the link's send slot is
    /// taken. Nothing changed.
    Busy,
    /// The link refused the call.
    Link(crate::zenoh_link::Error),
}

impl From<SessionError> for ServiceError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

/// One grant row: a holder, one exact key and the rights to publish and to subscribe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row<'k> {
    /// The index of the holder, below the declared holder count.
    pub holder: usize,
    pub key: &'k str,
    pub publish: bool,
    pub subscribe: bool,
}

/// One sample in a holder's ring. A holder that subscribes to several keys tells them apart by
/// `subscription`, the id of the subscription that matched, which is the one the core declared for the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample<const P: usize> {
    pub sequence: i64,
    pub timestamp: i64,
    pub subscription: u16,
    len: u32,
    payload: [u8; P],
}

impl<const P: usize> Sample<P> {
    const EMPTY: Self = Self {
        sequence: 0,
        timestamp: 0,
        subscription: 0,
        len: 0,
        payload: [0; P],
    };

    fn new(subscription: u16, sequence: i64, timestamp: i64, payload: &[u8]) -> Option<Self> {
        let mut copy = [0u8; P];
        copy.get_mut(..payload.len())?.copy_from_slice(payload);
        Some(Self {
            sequence,
            timestamp,
            subscription,
            len: u32::try_from(payload.len()).ok()?,
            payload: copy,
        })
    }

    pub fn payload(&self) -> &[u8] {
        self.payload
            .get(..usize::try_from(self.len).unwrap_or(0))
            .unwrap_or(&[])
    }
}

/// What a take returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item<const P: usize> {
    /// Samples were dropped from the ring since the last take. This is said once.
    Lost {
        count: u32,
    },
    Sample(Sample<P>),
}

/// Whether a publication was written to the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// The peer declared a subscriber on the key, and a batch of `sent` bytes was written.
    Sent { sent: usize },
    /// The peer declared no subscriber on the key. The local copies still arrived.
    NotSubscribed,
}

/// What an accepted publication did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Published {
    /// The holders whose rings took a copy.
    pub reached: usize,
    pub peer: Peer,
}

/// A ring of `N` slots that keeps the newest samples.
#[derive(Clone, Copy, Debug)]
struct Ring<const N: usize, const P: usize> {
    slots: [Sample<P>; N],
    /// The oldest sample.
    head: u16,
    held: u16,
    lost: u32,
}

impl<const N: usize, const P: usize> Ring<N, P> {
    const EMPTY: Self = Self {
        slots: [Sample::EMPTY; N],
        head: 0,
        held: 0,
        lost: 0,
    };

    /// Appends a sample. A full ring drops its oldest and counts the loss.
    fn push(&mut self, sample: Sample<P>) {
        if usize::from(self.held) == N {
            self.head = ((usize::from(self.head) + 1) % N) as u16;
            self.held -= 1;
            self.lost = self.lost.saturating_add(1);
        }
        let at = (usize::from(self.head) + usize::from(self.held)) % N;
        if let Some(slot) = self.slots.get_mut(at) {
            *slot = sample;
            self.held += 1;
        }
    }

    /// The item `take` would return next, without taking it.
    fn peek(&self) -> Option<Item<P>> {
        if self.lost > 0 {
            return Some(Item::Lost { count: self.lost });
        }
        if self.held == 0 {
            return None;
        }
        self.slots
            .get(usize::from(self.head))
            .copied()
            .map(Item::Sample)
    }

    fn take(&mut self) -> Option<Item<P>> {
        if self.lost > 0 {
            let count = self.lost;
            self.lost = 0;
            return Some(Item::Lost { count });
        }
        if self.held == 0 {
            return None;
        }
        let sample = *self.slots.get(usize::from(self.head))?;
        self.head = ((usize::from(self.head) + 1) % N) as u16;
        self.held -= 1;
        Some(Item::Sample(sample))
    }
}

/// A row as the core stores it.
#[derive(Clone, Copy, Debug)]
struct Stored<'k> {
    key: &'k str,
    holder: u16,
    /// The id of the subscription that serves this row, from 1, or 0 for a row that does not subscribe.
    subscription: u16,
    publish: bool,
    subscribe: bool,
}

impl Stored<'_> {
    const EMPTY: Stored<'static> = Stored {
        key: "",
        holder: 0,
        subscription: 0,
        publish: false,
        subscribe: false,
    };
}

/// The stored size of each part beyond its payload bytes and keys, in bytes. The grants contract states an
/// upper bound for each, and the declared stack is computed from those bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    /// A delivery slot beyond its payload.
    pub slot: usize,
    /// A grant row with its two key references.
    pub row: usize,
    /// A holder's ring beyond its slots.
    pub holder: usize,
    /// The core beyond its rows and rings.
    pub fixed: usize,
}

/// The core over `H` holders, ring slots of `N` samples of `P` payload bytes, and `R` rows.
#[derive(Debug)]
pub struct Core<'k, const H: usize, const N: usize, const P: usize, const R: usize> {
    rows: [Stored<'k>; R],
    /// How many of the `R` slots hold a granted row. The rest are empty and belong to no holder.
    used: usize,
    rings: [Ring<N, P>; H],
    params: Params,
    gid: [u8; GID_BYTES],
    /// How many distinct subscribe keys the rows name, and how many of them are declared.
    subscriptions: u16,
    declared: u16,
    /// Whether a declaration or a publication queued through a link has not yet been settled. Every
    /// [`OverLink`] over this core sees it, so two of them cannot each queue a frame.
    in_flight: bool,
}

impl<'k, const H: usize, const N: usize, const P: usize, const R: usize> Core<'k, H, N, P, R> {
    /// The widths the stored fields have, and the contract's bounds on what the core stores. Evaluated
    /// when a core is built, so a layout that outgrows the declared stack does not compile.
    const FITS: () = {
        assert!(H >= 1 && H <= u16::MAX as usize, "holders fit 16 bits");
        assert!(N >= 1 && N <= u16::MAX as usize, "ring slots fit 16 bits");
        assert!(R <= u16::MAX as usize, "rows fit 16 bits");
        assert!(P <= u32::MAX as usize, "a sample length fits 32 bits");
        let sizes = Self::sizes();
        assert!(
            sizes.slot <= SLOT_OVERHEAD_BYTES as usize,
            "slot over its bound"
        );
        assert!(
            sizes.row <= ROW_OVERHEAD_BYTES as usize,
            "row over its bound"
        );
        assert!(
            sizes.holder <= HOLDER_OVERHEAD_BYTES as usize,
            "holder over its bound"
        );
        assert!(
            sizes.fixed <= SERVICE_FIXED_BYTES as usize,
            "core over its bound"
        );
    };

    /// Puts the core at `declared` of `subscriptions` declared, so a test can reach the last id.
    #[cfg(test)]
    pub(crate) fn pretend_declared(&mut self, declared: u16, subscriptions: u16) {
        self.declared = declared;
        self.subscriptions = subscriptions;
    }

    /// The stored size of each part, from the layout.
    pub const fn sizes() -> Sizes {
        let slot = core::mem::size_of::<Sample<P>>() - P;
        let row = core::mem::size_of::<Stored<'static>>() + core::mem::size_of::<&str>();
        let rings = H * core::mem::size_of::<Ring<N, P>>();
        Sizes {
            slot,
            row,
            holder: core::mem::size_of::<Ring<N, P>>() - N * core::mem::size_of::<Sample<P>>(),
            fixed: core::mem::size_of::<Self>()
                - R * core::mem::size_of::<Stored<'static>>()
                - rings,
        }
    }

    /// A core declared with `rows`, for a session declared with `params`. `gid` is the 16-byte identity the
    /// core writes into the attachment of what it publishes.
    ///
    /// The grants are refused as [`ServiceError::InvalidGrants`] when there are no rows or more than `R`, a row
    /// names a holder beyond `H`, a key is empty or longer than the session's key bound, two rows name the
    /// same holder and key, a row grants no right, the rows name more subscribe keys than the session may
    /// declare, a ring slot is not the session's payload bound, or the session reassembles fragments.
    pub fn new(
        rows: &[Row<'k>],
        gid: [u8; GID_BYTES],
        params: &Params,
    ) -> Result<Self, ServiceError> {
        let () = Self::FITS;
        if rows.is_empty() || rows.len() > R || P != params.bounds.payload || params.fragments {
            return Err(ServiceError::InvalidGrants);
        }
        let mut stored = [Stored::EMPTY; R];
        let mut subscriptions = 0u16;
        for (index, row) in rows.iter().enumerate() {
            let granted = row.publish || row.subscribe;
            let key_fits = !row.key.is_empty() && row.key.len() <= params.bounds.key;
            let repeated = rows
                .iter()
                .take(index)
                .any(|earlier| earlier.holder == row.holder && earlier.key == row.key);
            if row.holder >= H || !granted || !key_fits || repeated {
                return Err(ServiceError::InvalidGrants);
            }
            let mut subscription = 0;
            if row.subscribe {
                // The key of an earlier subscribing row keeps its number.
                let known = stored
                    .iter()
                    .take(index)
                    .find(|earlier| earlier.subscription != 0 && earlier.key == row.key);
                subscription = match known {
                    Some(earlier) => earlier.subscription,
                    None => {
                        subscriptions += 1;
                        subscriptions
                    }
                };
            }
            if let Some(slot) = stored.get_mut(index) {
                *slot = Stored {
                    key: row.key,
                    holder: row.holder as u16,
                    subscription,
                    publish: row.publish,
                    subscribe: row.subscribe,
                };
            }
        }
        if usize::from(subscriptions) > params.local {
            return Err(ServiceError::InvalidGrants);
        }
        Ok(Self {
            rows: stored,
            used: rows.len(),
            rings: [Ring::EMPTY; H],
            params: *params,
            gid,
            subscriptions,
            declared: 0,
            in_flight: false,
        })
    }

    /// How many distinct subscribe keys the rows name, which is how many subscriptions the core declares.
    pub const fn subscriptions(&self) -> usize {
        self.subscriptions as usize
    }

    /// How many of those subscriptions the core has declared.
    pub const fn declared(&self) -> usize {
        self.declared as usize
    }

    fn check<const K: usize, const S: usize, const B: usize, const E: usize>(
        &self,
        session: &SessionOf<K, S, B, E>,
    ) -> Result<(), ServiceError> {
        if session.params() == &self.params {
            Ok(())
        } else {
            Err(ServiceError::WrongSession)
        }
    }

    /// Declares the next subscription to the peer and returns the length of the batch written to `out`, or
    /// `None` when every subscription is declared. The session must be open. A refusal declares nothing.
    pub fn declare_next<const K: usize, const S: usize, const B: usize, const E: usize>(
        &mut self,
        session: &mut SessionOf<K, S, B, E>,
        out: &mut [u8],
    ) -> Result<Option<usize>, ServiceError> {
        self.check(session)?;
        if self.declared == self.subscriptions {
            return Ok(None);
        }
        let id = self.declared + 1;
        let row = self
            .rows
            .iter()
            .find(|row| row.subscription == id)
            .ok_or(ServiceError::InvalidGrants)?;
        let outcome = session.send_declare_subscriber(u32::from(id), row.key, out)?;
        self.declared = id;
        Ok(Some(outcome.sent))
    }

    /// Publishes `payload` on `key` for `holder`. The holder needs a row that grants the right to publish
    /// the key. Every holder with a subscribe row on the key takes a copy, the publisher included. The peer
    /// is sent a FRAME in `out` only if it declared a subscriber on the key. A refusal reaches no ring and
    /// writes nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn publish<const K: usize, const S: usize, const B: usize, const E: usize>(
        &mut self,
        session: &mut SessionOf<K, S, B, E>,
        holder: usize,
        key: &str,
        sequence: i64,
        timestamp: i64,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Published, ServiceError> {
        self.check(session)?;
        if holder >= H {
            return Err(ServiceError::UnknownHolder);
        }
        let granted = self
            .rows
            .iter()
            .any(|row| usize::from(row.holder) == holder && row.publish && row.key == key);
        if !granted {
            return Err(ServiceError::NotGranted);
        }
        if payload.len() > P {
            return Err(ServiceError::TooLarge);
        }
        // A session that is not open cannot have the peer's declaration, and its refusal would read as the
        // peer having declared nothing. Say so as what it is.
        if !session.is_open() {
            return Err(SessionError::NotOpen.into());
        }
        // The peer's copy goes first, so a refusal by the session leaves every ring as it was.
        let attachment =
            encode::attachment(sequence, timestamp, &self.gid).map_err(SessionError::from)?;
        let peer = match session.send_put(key, &attachment, payload, out) {
            Ok(outcome) => Peer::Sent { sent: outcome.sent },
            Err(SessionError::UndeclaredKey) => Peer::NotSubscribed,
            Err(error) => return Err(error.into()),
        };
        let reached = self.deliver_key(key, sequence, timestamp, payload);
        Ok(Published { reached, peer })
    }

    /// Hands a batch from the peer to the session and delivers each sample it yields to every holder with a
    /// subscribe row on the subscription that matched. A Put for a key no subscription holds is refused by
    /// the session as `undeclared-key`, and then no ring changes.
    pub fn on_batch<'a, const K: usize, const S: usize, const B: usize, const E: usize>(
        &mut self,
        session: &mut SessionOf<K, S, B, E>,
        batch: &'a [u8],
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, ServiceError> {
        self.check(session)?;
        let outcome = session.on_batch(batch, now_ms, out)?;
        for event in outcome.events.iter() {
            if let Event::SampleDelivered {
                subscription,
                sequence,
                timestamp,
                payload,
            } = *event
            {
                self.deliver_subscription(subscription, sequence, timestamp, payload);
            }
        }
        Ok(outcome)
    }

    /// The oldest item in `holder`'s ring: a loss, said once, or a sample.
    pub fn take(&mut self, holder: usize) -> Result<Option<Item<P>>, ServiceError> {
        let ring = self
            .rings
            .get_mut(holder)
            .ok_or(ServiceError::UnknownHolder)?;
        Ok(ring.take())
    }

    /// The item `take` would return next for `holder`, left in its ring. A caller whose buffer is too small for
    /// a sample looks first, so the sample stays and nothing is lost.
    pub fn peek(&self, holder: usize) -> Result<Option<Item<P>>, ServiceError> {
        let ring = self.rings.get(holder).ok_or(ServiceError::UnknownHolder)?;
        Ok(ring.peek())
    }

    /// The index of `holder`'s own row that a sample of `subscription` belongs to, counted among that holder's
    /// rows in grant order. A holder sees its rows by this index and never by key.
    pub fn row_of(&self, holder: usize, subscription: u16) -> Option<usize> {
        self.rows[..self.used]
            .iter()
            .filter(|row| usize::from(row.holder) == holder)
            .position(|row| row.subscribe && row.subscription == subscription)
    }

    /// How many rows `holder` has.
    pub fn row_count(&self, holder: usize) -> usize {
        self.rows[..self.used]
            .iter()
            .filter(|row| usize::from(row.holder) == holder)
            .count()
    }

    /// The key of `holder`'s row `index`, and whether the row grants publish.
    pub fn row_key(&self, holder: usize, index: usize) -> Option<(&'k str, bool)> {
        self.rows[..self.used]
            .iter()
            .filter(|row| usize::from(row.holder) == holder)
            .nth(index)
            .map(|row| (row.key, row.publish))
    }

    /// The samples `holder`'s ring holds and the loss it has counted.
    pub fn held(&self, holder: usize) -> Result<(usize, u32), ServiceError> {
        let ring = self.rings.get(holder).ok_or(ServiceError::UnknownHolder)?;
        Ok((usize::from(ring.held), ring.lost))
    }

    fn push_to(&mut self, row: Stored<'_>, sequence: i64, timestamp: i64, payload: &[u8]) -> bool {
        let Some(sample) = Sample::new(row.subscription, sequence, timestamp, payload) else {
            return false;
        };
        let Some(ring) = self.rings.get_mut(usize::from(row.holder)) else {
            return false;
        };
        ring.push(sample);
        true
    }

    fn deliver_key(&mut self, key: &str, sequence: i64, timestamp: i64, payload: &[u8]) -> usize {
        let mut reached = 0;
        for index in 0..self.used {
            let Some(row) = self.rows.get(index).copied() else {
                continue;
            };
            if row.subscribe && row.key == key && self.push_to(row, sequence, timestamp, payload) {
                reached += 1;
            }
        }
        reached
    }

    fn deliver_subscription(
        &mut self,
        subscription: u32,
        sequence: i64,
        timestamp: i64,
        payload: &[u8],
    ) {
        for index in 0..self.used {
            let Some(row) = self.rows.get(index).copied() else {
                continue;
            };
            if row.subscribe && u32::from(row.subscription) == subscription {
                self.push_to(row, sequence, timestamp, payload);
            }
        }
    }
}
