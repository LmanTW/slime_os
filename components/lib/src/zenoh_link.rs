//! Zenoh Profile 0 transport runtime: one [`Session`] over a [`ByteLink`].
//!
//! Every buffer is sized by const generics from the link's declaration; the heap a fragmented message
//! is joined into belongs to the owning component, which lends it on every pump. A pump that finds the
//! send slot free lets the session add a KEEP_ALIVE
//! when one is due; with a batch waiting it only checks the lease. The link holds at most one framed batch awaiting send
//! and never drops a received batch: while the send slot is busy the next batch
//! stays in the [`StreamFramer`] until a reply can be queued. A [`LinkHandle`]
//! carries the generation of the link that issued it, so a restart, which builds
//! a new link under the next generation, cannot be driven through an old handle.

use crate::zenoh_profile0::encode::{self, EncodeError};
use crate::zenoh_profile0::lane::{Lane, peek_fragment_lane};
use crate::zenoh_profile0::session::{
    Config, DropCause, Event, MAX_EVENTS, Outcome, Params, Role, SessionError, SessionOf, State,
};
use crate::zenoh_profile0::{
    MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, Qos, Refusal, STREAM_LENGTH_BYTES,
    StreamFramerOf,
};

#[cfg(test)]
#[path = "zenoh_link/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "zenoh_link/router_tests.rs"]
mod router_tests;

#[cfg(test)]
#[path = "zenoh_link/put_tests.rs"]
mod put_tests;

#[cfg(test)]
#[path = "zenoh_link/token_tests.rs"]
mod token_tests;

/// Consecutive stalled sends tolerated before the link gives up; the demo contract's `maxRetries`.
pub const MAX_RETRIES: u32 = 3;
/// The framed size of the first release's batch.
const DEMO_FRAMED: usize = STREAM_LENGTH_BYTES + MAX_BATCH_BYTES;
const READ_CHUNK: usize = 64;

/// What the byte stream beneath a link can do.
pub trait ByteLink {
    /// Accepts up to `buf.len()` bytes and returns how many it took; 0 means it would block.
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError>;
    /// Fills up to `buf.len()` bytes; `Ok(0)` while [`eof`](Self::eof) is false means it would block.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError>;
    /// Whether the peer has closed its half and everything it sent has been read.
    fn eof(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    Reset,
    Closed,
}

/// What [`LinkOf::publish_qos`] did with a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    /// The frame is in the send slot.
    Queued,
    /// The send slot was busy and the publication does not block, so it was discarded and counted.
    Dropped,
}

/// Why the link refuses an operation or ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The byte stream failed.
    Link(LinkError),
    /// The stream carried a length prefix or a batch the profile refuses.
    Stream(Refusal),
    /// The session machine refused the batch or the request.
    Session(SessionError),
    /// The encoder refused to frame the batch.
    Encode(EncodeError),
    /// A send stalled more than [`MAX_RETRIES`] times in a row.
    RetryLimit,
    /// A batch is still waiting to be sent.
    SendBusy,
    /// A received batch would not fit the reassembly buffer.
    ReceiveQueueFull,
    /// The link is closed.
    SendAfterClose,
    /// The handle was issued by an earlier link generation.
    StaleHandle,
    /// A Put too large for one frame, which a link that reassembles sends with [`PutSend`].
    NeedsFragments,
}

impl From<SessionError> for Error {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<EncodeError> for Error {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// Proof that a caller holds the link of one generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkHandle {
    generation: u32,
}

/// What one [`Link::pump`] saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PumpReport {
    pub batches: usize,
    pub sent_bytes: usize,
    pub received_bytes: usize,
}

/// A sample the link delivered; the payload is a bounded copy of `P` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample<const P: usize = MAX_PAYLOAD_BYTES> {
    /// The id of the subscription this side declared on the key, which matched the Put.
    pub subscription: u32,
    pub sequence: i64,
    pub timestamp: i64,
    pub len: usize,
    pub payload: [u8; P],
}

impl<const P: usize> Sample<P> {
    pub fn payload(&self) -> &[u8] {
        self.payload.get(..self.len).unwrap_or(&[])
    }
}

/// A sample a heap link joined from fragments: where it lies in the heap the owner lends. It stays
/// there until a later message is joined over its cell, which is not before the next one completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredSample {
    pub sequence: i64,
    pub timestamp: i64,
    /// The byte of the heap the payload starts at.
    pub start: usize,
    pub len: usize,
}

impl StoredSample {
    /// The payload, read from the heap the link was lent.
    pub fn payload<'h>(&self, heap: &'h [u8]) -> &'h [u8] {
        heap.get(self.start..self.start + self.len).unwrap_or(&[])
    }
}

/// What the owner of the link observes, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice<const P: usize = MAX_PAYLOAD_BYTES> {
    HandshakeComplete,
    SubscriberDeclared {
        id: u32,
    },
    SampleDelivered(Sample<P>),
    /// A sample joined from fragments into the heap the owner lends.
    SampleStored(StoredSample),
    SubscriberUndeclared {
        id: u32,
    },
    Closed {
        reason: u8,
    },
}

/// An owned copy of one batch body, kept so a node can report the exact bytes it exchanged.
#[derive(Clone, Copy)]
struct Tap<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Tap<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn keep(&mut self, batch: &[u8]) {
        let len = batch.len().min(N);
        if let (Some(dst), Some(src)) = (self.bytes.get_mut(..len), batch.get(..len)) {
            dst.copy_from_slice(src);
            self.len = len;
        }
    }

    fn get(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

/// Notices not yet taken by the owner; a full queue stops draining.
const DEMO_NOTICES: usize = 2 * MAX_EVENTS;

/// A link over a byte stream. Every buffer is sized from the declaration: `FRAMED` is the batch the
/// link announces with its stream length, `K` and `S` the aliases and subscribers its session holds,
/// `B` the longest key, `P` the payload a fixed link copies into each notice (0 in heap mode, where a
/// sample is a range of the heap), and `Q` the notices queued before draining stops.
pub struct LinkOf<
    L: ByteLink,
    const FRAMED: usize,
    const K: usize,
    const S: usize,
    const B: usize,
    const P: usize,
    const Q: usize,
    const E: usize = MAX_EVENTS,
    const R: usize = 1,
> {
    io: L,
    session: SessionOf<K, S, B, E, R>,
    framer: StreamFramerOf<FRAMED>,
    send: [u8; FRAMED],
    send_len: usize,
    sent: usize,
    stalls: u32,
    generation: u32,
    closed: bool,
    notices: [Option<Notice<P>>; Q],
    notice_head: usize,
    notice_len: usize,
    /// Where the search for a free heap cell begins: the cell after the one the last stored sample took.
    cell_next: usize,
    /// How many queued notices hold a stored sample, each of which occupies one heap cell.
    stored: usize,
    /// The best-effort drops the session reported and the owner has not taken, oldest first, and how many arrived
    /// with no room to hold them. A drop is a count for the owner and not a notice, so it never takes a slot a
    /// sample needs.
    drops: [Option<(u8, DropCause)>; E],
    drops_held: usize,
    drops_lost: u32,
    /// The publications [`publish_qos`](Self::publish_qos) discarded because the send slot was busy. It saturates.
    dropped: u32,
    /// The heap cell each open run of the session is joined into, valid while the run is open.
    run_cell: [usize; R],
    /// The cell the fragment being applied is joined into, which a completed message is stored in.
    fragment_cell: usize,
    /// The body of the last batch queued for send and of the last one received, for evidence.
    tap_sent: Tap<FRAMED>,
    tap_received: Tap<FRAMED>,
}

/// The first release's link: a 512-byte batch, one alias and one subscriber of each side, a 129-byte key
/// and a 12-byte payload.
pub type Link<L> =
    LinkOf<L, DEMO_FRAMED, 1, 2, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, DEMO_NOTICES, MAX_EVENTS>;

impl<L: ByteLink> Link<L> {
    /// A link in its generation under the first release's parameters, with a fresh session and
    /// nothing queued.
    pub fn new(
        io: L,
        role: Role,
        config: &Config<'_>,
        generation: u32,
    ) -> Result<Self, SessionError> {
        Self::with_params(io, role, config, Params::DEMO, generation)
    }
}

impl<
    L: ByteLink,
    const FRAMED: usize,
    const K: usize,
    const S: usize,
    const B: usize,
    const P: usize,
    const Q: usize,
    const E: usize,
    const R: usize,
> LinkOf<L, FRAMED, K, S, B, P, Q, E, R>
{
    /// The same link with the client role on its session: it announces itself as a client, takes the INIT_ACK of a
    /// router and takes the timestamp of a Put a router forwards. A listener, and a link that has begun its
    /// handshake, are `InvalidConfig`.
    pub fn with_client_role(mut self) -> Result<Self, SessionError> {
        self.session = self.session.with_client_role()?;
        Ok(self)
    }

    /// A link in its generation, declared by `params`, whose session holds one run.
    pub fn with_params(
        io: L,
        role: Role,
        config: &Config<'_>,
        params: Params,
        generation: u32,
    ) -> Result<Self, SessionError> {
        Self::with_lanes(io, role, config, params, 1, generation)
    }

    /// A link in its generation, declared by `params`, whose session holds `runs` runs. `runs` must be `R`. A
    /// link with 2 or more offers the QoS unit extension, and one whose peer offers it too takes the lanes.
    pub fn with_lanes(
        io: L,
        role: Role,
        config: &Config<'_>,
        params: Params,
        runs: usize,
        generation: u32,
    ) -> Result<Self, SessionError> {
        if params.bounds.batch + STREAM_LENGTH_BYTES != FRAMED {
            return Err(SessionError::InvalidConfig);
        }
        // The storage is exactly what the configuration declares. A fixed link copies each payload into its
        // notice, so the notice holds the declared payload; a heap link keeps samples in the heap and its
        // notices carry none. The queue holds two notices for each sample the owner may hold unread.
        if (!params.fragments && params.bounds.payload != P)
            || params.samples.saturating_mul(2) != Q
        {
            return Err(SessionError::InvalidConfig);
        }
        Ok(Self {
            io,
            session: SessionOf::with_lanes(role, config, params, runs)?,
            framer: StreamFramerOf::new(),
            send: [0; FRAMED],
            send_len: 0,
            sent: 0,
            stalls: 0,
            generation,
            closed: false,
            notices: [None; Q],
            notice_head: 0,
            notice_len: 0,
            cell_next: 0,
            stored: 0,
            drops: [None; E],
            drops_held: 0,
            drops_lost: 0,
            dropped: 0,
            run_cell: [0; R],
            fragment_cell: 0,
            tap_sent: Tap::new(),
            tap_received: Tap::new(),
        })
    }

    pub const fn handle(&self) -> LinkHandle {
        LinkHandle {
            generation: self.generation,
        }
    }

    /// The body of the most recent batch this link queued for send, without the stream prefix.
    pub fn last_sent_batch(&self) -> &[u8] {
        self.tap_sent.get()
    }

    /// The body of the batch behind the notices queued by the latest [`pump`](Self::pump).
    pub fn last_received_batch(&self) -> &[u8] {
        self.tap_received.get()
    }

    pub fn session(&self) -> &SessionOf<K, S, B, E, R> {
        &self.session
    }

    pub fn io(&self) -> &L {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut L {
        &mut self.io
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether a framed batch is waiting to be sent.
    pub const fn send_pending(&self) -> bool {
        self.send_len != 0
    }

    /// Notices queued and not yet taken.
    pub const fn notices_queued(&self) -> usize {
        self.notice_len
    }

    /// Takes the oldest notice.
    pub fn next_notice(&mut self) -> Option<Notice<P>> {
        if self.notice_len == 0 {
            return None;
        }
        let notice = self.notices.get_mut(self.notice_head)?.take();
        self.notice_head = (self.notice_head + 1) % Q;
        self.notice_len -= 1;
        if matches!(notice, Some(Notice::SampleStored(_))) {
            self.stored -= 1;
        }
        notice
    }

    /// The oldest best-effort drop the owner has not taken: the priority of the lane and why it dropped. A link
    /// holds as many as its session reports in one batch. One that arrives with no room is counted by
    /// [`drops_lost`](Self::drops_lost) and not kept, so the owner takes them after each pump.
    pub fn take_drop(&mut self) -> Option<(u8, DropCause)> {
        if self.drops_held == 0 {
            return None;
        }
        let first = self.drops.get_mut(0)?.take();
        self.drops.rotate_left(1);
        self.drops_held -= 1;
        first
    }

    /// How many drops arrived while the link already held as many as its session reports in one batch.
    pub const fn drops_lost(&self) -> u32 {
        self.drops_lost
    }

    fn note_drop(&mut self, priority: u8, cause: DropCause) {
        match self.drops.get_mut(self.drops_held) {
            Some(slot) => {
                *slot = Some((priority, cause));
                self.drops_held += 1;
            }
            None => self.drops_lost = self.drops_lost.saturating_add(1),
        }
    }

    fn check(&self, handle: LinkHandle) -> Result<(), Error> {
        if handle.generation != self.generation {
            return Err(Error::StaleHandle);
        }
        if self.closed {
            return Err(Error::SendAfterClose);
        }
        Ok(())
    }

    fn push_notice(&mut self, notice: Notice<P>) {
        // A full queue keeps what it holds: a notice that has nowhere to go is not written over the oldest.
        if self.notice_len >= Q {
            return;
        }
        let at = (self.notice_head + self.notice_len) % Q;
        if let Some(slot) = self.notices.get_mut(at) {
            *slot = Some(notice);
            self.notice_len += 1;
        }
    }

    fn notice_room(&self, needed: usize) -> bool {
        Q - self.notice_len >= needed
    }

    /// Frames `batch` into the send slot, which must be free.
    fn queue(&mut self, batch: &[u8]) -> Result<(), Error> {
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let written =
            encode::stream_batch_max(&mut self.send, batch, FRAMED - STREAM_LENGTH_BYTES)?;
        self.tap_sent.keep(batch);
        self.send_len = written;
        self.sent = 0;
        Ok(())
    }

    /// Queues the connector's INIT_SYN.
    pub fn open(&mut self, handle: LinkHandle, now_ms: u64) -> Result<(), Error> {
        self.check(handle)?;
        let mut body = [0u8; FRAMED];
        let outcome = self.session.connect(now_ms, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Queues a PUSH carrying `payload` under `key`, whole in one FRAME. A Put too large for one FRAME is
    /// refused as [`Error::NeedsFragments`] by a link that reassembles, and sent with
    /// [`publish_part`](Self::publish_part).
    pub fn publish(
        &mut self,
        handle: LinkHandle,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
    ) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = match self.session.send_put(key, attachment, payload, &mut body) {
            Err(SessionError::NeedsFragments) => return Err(Error::NeedsFragments),
            other => other?,
        };
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// [`publish`](Self::publish) with the QoS the PUSH states. With the send slot free it queues the frame, as
    /// `publish` does. With the slot busy the congestion control decides: a Block publication is refused as
    /// [`Error::SendBusy`] and changes nothing, and any other is discarded and counted by
    /// [`dropped`](Self::dropped). A discarded publication builds no frame, so the session spends no sequence
    /// number and the next frame sent follows the last one sent. A Put the link could never send is refused whether
    /// the slot is busy or not.
    pub fn publish_qos(
        &mut self,
        handle: LinkHandle,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        qos: Qos,
    ) -> Result<Published, Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            if qos.block() {
                return Err(Error::SendBusy);
            }
            match self.session.check_whole_put(key, attachment, payload.len()) {
                Err(SessionError::NeedsFragments) => return Err(Error::NeedsFragments),
                other => other?,
            }
            self.dropped = self.dropped.saturating_add(1);
            return Ok(Published::Dropped);
        }
        let mut body = [0u8; FRAMED];
        let outcome = match self
            .session
            .send_put_qos(key, attachment, payload, qos, &mut body)
        {
            Err(SessionError::NeedsFragments) => return Err(Error::NeedsFragments),
            other => other?,
        };
        let batch = outcome.batch(&body);
        self.queue(batch)?;
        Ok(Published::Queued)
    }

    /// How many publications [`publish_qos`](Self::publish_qos) discarded because the send slot was busy.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Queues the next FRAGMENT of a Put, starting at byte `at` of its message (0 for the first), and
    /// returns where to resume, or `None` once the last fragment is queued. Each call needs the send slot
    /// free, so the owner pumps between calls.
    pub fn publish_part(
        &mut self,
        handle: LinkHandle,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        at: usize,
    ) -> Result<Option<usize>, Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let (outcome, next) = self
            .session
            .send_put_fragment(key, attachment, payload, at, &mut body)?;
        let batch = outcome.batch(&body);
        if !batch.is_empty() {
            self.queue(batch)?;
        }
        Ok(next)
    }

    pub fn declare_subscriber(
        &mut self,
        handle: LinkHandle,
        id: u32,
        key: &str,
    ) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.send_declare_subscriber(id, key, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Queues the declaration of the liveliness token `id` under `key`, written in full. Only a link with the client role
    /// writes one.
    pub fn declare_token(&mut self, handle: LinkHandle, id: u32, key: &str) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.send_declare_token(id, key, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Queues the withdrawal of the liveliness token `id`.
    pub fn withdraw_token(&mut self, handle: LinkHandle, id: u32) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.send_undeclare_token(id, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    pub fn undeclare_subscriber(
        &mut self,
        handle: LinkHandle,
        id: u32,
        key: &str,
    ) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.send_undeclare_subscriber(id, key, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Queues CLOSE and ends the link. Refused with [`Error::SendBusy`], changing nothing, while a
    /// batch is still waiting to be sent: a CLOSE that is never queued would leave the peer open.
    pub fn close(&mut self, handle: LinkHandle, reason: u8) -> Result<(), Error> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.close(reason, &mut body)?;
        self.absorb(&outcome, &mut []);
        self.queue(outcome.batch(&body))?;
        self.closed = true;
        Ok(())
    }

    /// The cells `heap_len` bytes hold, one message each; a heap shorter than one message still has one
    /// cell, which a join then finds too small.
    fn cells(&self, heap_len: usize) -> usize {
        match self.session.params().message_limit {
            0 => 1,
            limit => (heap_len / limit).max(1),
        }
    }

    /// Whether `cell` holds a message: an open run is joined into it, or a queued notice points into it.
    fn cell_busy(&self, cell: usize) -> bool {
        let limit = self.session.params().message_limit;
        let run = (0..R).any(|slot| self.session.run_open(slot) && self.run_cell[slot] == cell);
        // With one run, messages complete in the order their cells were taken, so the cell after the last one
        // taken is free whenever a cell is. Only several runs can finish out of order, and they pay for the scan.
        if R == 1 || self.stored == 0 {
            return run;
        }
        run || (0..self.notice_len).any(|at| {
            let held = self.notices[(self.notice_head + at) % Q];
            matches!(held, Some(Notice::SampleStored(sample)) if limit != 0 && sample.start / limit == cell)
        })
    }

    /// The first cell no message occupies, searching from the cell after the last stored sample's.
    fn free_cell(&self, heap_len: usize) -> Option<usize> {
        let cells = self.cells(heap_len);
        (0..cells)
            .map(|step| (self.cell_next + step) % cells)
            .find(|cell| !self.cell_busy(*cell))
    }

    /// How many cells no message occupies: every cell, less one for each stored sample and one for each open run.
    /// It reads two counters and the run table, so a pass over a long notice queue does not pay for it.
    fn free_cells(&self, heap_len: usize) -> usize {
        let open = (0..R).filter(|slot| self.session.run_open(*slot)).count();
        self.cells(heap_len).saturating_sub(self.stored + open)
    }

    /// Turns a session's events into notices. A heap link keeps every sample in the heap the owner lent,
    /// whether it arrived whole or in fragments, so its notices carry no payload of their own.
    fn absorb(&mut self, outcome: &Outcome<'_, E>, heap: &mut [u8]) {
        for event in outcome.events.iter() {
            let notice = match *event {
                Event::HandshakeComplete => Notice::HandshakeComplete,
                Event::SubscriberDeclared { id } => Notice::SubscriberDeclared { id },
                Event::SubscriberUndeclared { id } => Notice::SubscriberUndeclared { id },
                Event::Closed { reason } => Notice::Closed { reason },
                Event::Dropped { priority, cause } => {
                    self.note_drop(priority, cause);
                    continue;
                }
                Event::SampleStored {
                    sequence,
                    timestamp,
                    offset,
                    len,
                } => {
                    let cell = self.fragment_cell;
                    let start = cell * self.session.params().message_limit + offset;
                    self.cell_next = cell + 1;
                    self.stored += 1;
                    Notice::SampleStored(StoredSample {
                        sequence,
                        timestamp,
                        start,
                        len,
                    })
                }
                Event::SampleDelivered {
                    sequence,
                    timestamp,
                    payload,
                    ..
                } if self.session.params().fragments => {
                    let Some(cell) = self.free_cell(heap.len()) else {
                        continue;
                    };
                    let start = cell * self.session.params().message_limit;
                    let Some(room) = heap.get_mut(start..start + payload.len()) else {
                        continue;
                    };
                    room.copy_from_slice(payload);
                    self.cell_next = cell + 1;
                    self.stored += 1;
                    Notice::SampleStored(StoredSample {
                        sequence,
                        timestamp,
                        start,
                        len: payload.len(),
                    })
                }
                Event::SampleDelivered {
                    subscription,
                    sequence,
                    timestamp,
                    payload,
                } => {
                    let mut copy = [0u8; P];
                    let len = payload.len().min(P);
                    if let (Some(dst), Some(src)) = (copy.get_mut(..len), payload.get(..len)) {
                        dst.copy_from_slice(src);
                    }
                    Notice::SampleDelivered(Sample {
                        subscription,
                        sequence,
                        timestamp,
                        len,
                        payload: copy,
                    })
                }
            };
            self.push_notice(notice);
        }
    }

    /// Ends the link after a stream or session refusal that makes the rest of the stream untrustworthy.
    fn fail(&mut self, error: Error) -> Error {
        let mut body = [0u8; FRAMED];
        if let Ok(outcome) = self.session.close(0, &mut body) {
            self.absorb(&outcome, &mut []);
            let batch = outcome.batch(&body);
            if self.send_len == 0 {
                let _ = self.queue(batch);
            }
        }
        self.closed = true;
        error
    }

    fn flush(&mut self) -> Result<usize, Error> {
        let mut total = 0;
        while self.send_len != 0 {
            let pending = self.send.get(self.sent..self.send_len).unwrap_or(&[]);
            let accepted = self.io.send(pending).map_err(Error::Link)?;
            if accepted == 0 {
                self.stalls += 1;
                if self.stalls > MAX_RETRIES {
                    return Err(Error::RetryLimit);
                }
                return Ok(total);
            }
            self.stalls = 0;
            self.sent += accepted.min(pending.len());
            total += accepted;
            if self.sent >= self.send_len {
                self.send_len = 0;
                self.sent = 0;
            }
        }
        Ok(total)
    }

    /// Drives the link once with no heap: a link that reassembles refuses a fragment as out of memory.
    pub fn pump(&mut self, handle: LinkHandle, now_ms: u64) -> Result<PumpReport, Error> {
        self.pump_with(handle, now_ms, &mut [])
    }

    /// Drives the link once: flush, read, decode and reply, then check the lease. `heap` is the storage a
    /// fragmented message is joined into, cut into cells of one message each, and the owner lends the same
    /// heap on every pump so a stored sample stays where it was put until its notice is taken.
    pub fn pump_with(
        &mut self,
        handle: LinkHandle,
        now_ms: u64,
        heap: &mut [u8],
    ) -> Result<PumpReport, Error> {
        if handle.generation != self.generation {
            return Err(Error::StaleHandle);
        }
        let mut report = PumpReport::default();
        if self.closed {
            report.sent_bytes = self.flush()?;
            return Ok(report);
        }
        report.sent_bytes = match self.flush() {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.fail(error)),
        };
        if report.sent_bytes != 0 {
            self.session.note_sent(now_ms);
        }
        self.fill(&mut report)?;
        self.drain(now_ms, heap, &mut report)?;
        if !self.closed {
            let mut body = [0u8; FRAMED];
            // The single send slot decides whether a keep-alive may be written at all: with a batch
            // waiting in it only the lease is checked, so the keep-alive never collides with that
            // batch and the batch goes out whole.
            let ticked = if self.send_len == 0 {
                self.session.tick(now_ms, &mut body)
            } else {
                self.session.tick_lease(now_ms, &mut body)
            };
            let outcome = match ticked {
                Ok(outcome) => outcome,
                Err(error) => return Err(self.fail(Error::Session(error))),
            };
            // Only a CLOSE ends the link. A best-effort drop reported by the same tick does not.
            let ended = outcome
                .events
                .iter()
                .any(|event| matches!(event, Event::Closed { .. }));
            self.absorb(&outcome, &mut []);
            if outcome.sent != 0 {
                let batch = outcome.batch(&body);
                if self.send_len == 0 {
                    self.queue(batch)?;
                }
                if ended {
                    self.closed = true;
                }
            }
        }
        let flushed = match self.flush() {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.fail(error)),
        };
        if flushed != 0 {
            self.session.note_sent(now_ms);
        }
        report.sent_bytes += flushed;
        Ok(report)
    }

    /// Reads what the stream offers into the reassembly buffer. A full buffer
    /// while a batch still cannot be completed means the peer sent more than one
    /// batch can hold: that is refused, never dropped silently.
    fn fill(&mut self, report: &mut PumpReport) -> Result<(), Error> {
        loop {
            let room = FRAMED - self.framer.pending();
            if room == 0 {
                // Whole batches are waiting on a free send slot or a notice slot: that is
                // backpressure, and the bytes stay in the stream until they can be taken.
                return match self.framer.peek_batch() {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err(self.fail(Error::ReceiveQueueFull)),
                    Err(refusal) => Err(self.fail(Error::Stream(refusal))),
                };
            }
            let mut chunk = [0u8; READ_CHUNK];
            let window = chunk.get_mut(..room.min(READ_CHUNK)).unwrap_or(&mut []);
            let read = match self.io.recv(window) {
                Ok(read) => read,
                Err(error) => return Err(self.fail(Error::Link(error))),
            };
            if read == 0 {
                // Bytes the peer sent before it closed are processed first; the end of the stream
                // is reported once nothing more can arrive.
                if self.io.eof() && self.framer.pending() == 0 {
                    return Err(self.fail(Error::Link(LinkError::Closed)));
                }
                return Ok(());
            }
            let held = window.get(..read).unwrap_or(&[]);
            let taken = self.framer.push(held);
            report.received_bytes += taken;
            // A prefix is judged as soon as it arrives, so a hostile length is refused before its body.
            if let Err(refusal) = self.framer.peek_batch() {
                return Err(self.fail(Error::Stream(refusal)));
            }
        }
    }

    fn drain(
        &mut self,
        now_ms: u64,
        heap: &mut [u8],
        report: &mut PumpReport,
    ) -> Result<(), Error> {
        loop {
            if self.closed || self.send_len != 0 {
                return Ok(());
            }
            let mut batch = [0u8; FRAMED];
            let len = match self.framer.peek_batch() {
                Ok(Some(found)) => {
                    let len = found.len();
                    if let (Some(dst), Some(src)) = (batch.get_mut(..len), found.get(..len)) {
                        dst.copy_from_slice(src);
                    }
                    len
                }
                Ok(None) => return Ok(()),
                Err(refusal) => return Err(self.fail(Error::Stream(refusal))),
            };
            let body = batch.get(..len).unwrap_or(&[]);
            let (needed, samples) = self.session.events_needed(body);
            if needed > Q {
                return Err(self.fail(Error::ReceiveQueueFull));
            }
            if !self.notice_room(needed) {
                return Ok(());
            }
            let heap_mode = self.session.params().fragments;
            let fragment = heap_mode
                && body
                    .first()
                    .copied()
                    .is_some_and(crate::zenoh_profile0::fragment::is_fragment);
            // A session with lanes reads the lane a fragment names. Without them every fragment is on the default
            // lane. The session names the slot the fragment takes, and the link owns the cell for that slot.
            let by_lane = fragment && self.session.lanes();
            let slot = if !fragment {
                None
            } else if by_lane {
                peek_fragment_lane(body).and_then(|lane| self.session.run_slot(lane))
            } else {
                self.session.run_slot(Lane::DEFAULT)
            };
            // The first fragment of a run is the one that claims the cell the whole message is joined into,
            // so it counts as a sample for room even though it yields none until the last arrives.
            let starts_run = slot.is_some_and(|slot| !self.session.run_open(slot));
            let samples = if starts_run { samples.max(1) } else { samples };
            // A heap link keeps every sample in the heap it was lent, so a sample the heap cannot hold is
            // refused before the session applies it and moves its sequence number.
            if heap_mode && samples > 0 && heap.len() < self.session.params().message_limit {
                return Err(self.fail(Error::Session(SessionError::OutOfMemory)));
            }
            // A heap link waits for a free cell for every sample the batch can yield: each cell holds a
            // message in progress or a sample the owner has not taken. A fragment that continues a run has
            // its cell already.
            let cells_needed = if !heap_mode {
                0
            } else if fragment {
                usize::from(starts_run)
            } else {
                samples
            };
            if self.free_cells(heap.len()) < cells_needed {
                return Ok(());
            }
            self.tap_received.keep(body);
            let limit = self.session.params().message_limit;
            let held = match slot {
                Some(slot) if self.session.run_open(slot) => Some(self.run_cell[slot]),
                Some(_) => self.free_cell(heap.len()),
                None => None,
            };
            if let (Some(slot), Some(cell)) = (slot, held) {
                self.run_cell[slot] = cell;
            }
            self.fragment_cell = held.unwrap_or(0);
            let cell_start = held.map_or(0, |cell| cell * limit).min(heap.len());
            let cell_end = if limit == 0 || held.is_none() {
                cell_start
            } else {
                (cell_start + limit).min(heap.len())
            };
            let cell = heap.get_mut(cell_start..cell_end).unwrap_or(&mut []);
            let mut reply = [0u8; FRAMED];
            let applied = if by_lane {
                self.session.on_lane_fragment(body, now_ms, cell)
            } else {
                self.session.on_batch_with(body, now_ms, &mut reply, cell)
            };
            let outcome = match applied {
                Ok(outcome) => outcome,
                Err(error) => return Err(self.fail(Error::Session(error))),
            };
            let observed = !outcome.events.is_empty();
            self.absorb(&outcome, heap);
            if self.session.state() == State::Closed {
                self.closed = true;
            }
            self.framer.consume_batch();
            report.batches += 1;
            let sent = outcome.batch(&reply);
            if !sent.is_empty() {
                self.queue(sent)?;
            }
            // A batch that raised notices ends the pass, so the batch tap still names the
            // batch behind the notices the owner is about to take.
            if observed {
                return Ok(());
            }
        }
    }

    /// Whether the session finished its handshake and is still open.
    pub fn is_open(&self) -> bool {
        self.session.state() == State::Open && !self.closed
    }
}
