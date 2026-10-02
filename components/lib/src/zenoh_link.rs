//! Zenoh Profile 0 transport runtime: one [`Session`] over a [`ByteLink`].
//!
//! Every buffer is fixed. The link holds at most one framed batch awaiting send
//! and never drops a received batch: while the send slot is busy the next batch
//! stays in the [`StreamFramer`] until a reply can be queued. A [`LinkHandle`]
//! carries the generation of the link that issued it, so a restart, which builds
//! a new link under the next generation, cannot be driven through an old handle.

use crate::zenoh_profile0::encode::{self, EncodeError};
use crate::zenoh_profile0::session::{
    Config, Event, MAX_EVENTS, Role, Session, SessionError, State,
};
use crate::zenoh_profile0::{MAX_BATCH_BYTES, Refusal, STREAM_LENGTH_BYTES, StreamFramer};

#[cfg(test)]
#[path = "zenoh_link/tests.rs"]
mod tests;

/// Consecutive stalled sends tolerated before the link gives up; the demo contract's `maxRetries`.
pub const MAX_RETRIES: u32 = 3;
const FRAMED_BYTES: usize = STREAM_LENGTH_BYTES + MAX_BATCH_BYTES;
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

/// A sample the link delivered; the payload is a bounded copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub sequence: i64,
    pub timestamp: i64,
    pub len: usize,
    pub payload: [u8; crate::zenoh_profile0::MAX_PAYLOAD_BYTES],
}

impl Sample {
    pub fn payload(&self) -> &[u8] {
        self.payload.get(..self.len).unwrap_or(&[])
    }
}

/// What the owner of the link observes, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    HandshakeComplete,
    SubscriberDeclared { id: u32 },
    SampleDelivered(Sample),
    SubscriberUndeclared { id: u32 },
    Closed { reason: u8 },
}

/// An owned copy of one batch body, kept so a node can report the exact bytes it exchanged.
#[derive(Clone, Copy)]
struct Tap {
    bytes: [u8; MAX_BATCH_BYTES],
    len: usize,
}

impl Tap {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_BATCH_BYTES],
            len: 0,
        }
    }

    fn keep(&mut self, batch: &[u8]) {
        let len = batch.len().min(MAX_BATCH_BYTES);
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
const NOTICES: usize = 2 * MAX_EVENTS;

pub struct Link<L: ByteLink> {
    io: L,
    session: Session,
    framer: StreamFramer,
    send: [u8; FRAMED_BYTES],
    send_len: usize,
    sent: usize,
    stalls: u32,
    generation: u32,
    closed: bool,
    notices: [Option<Notice>; NOTICES],
    notice_head: usize,
    notice_len: usize,
    /// The body of the last batch queued for send and of the last one received, for evidence.
    tap_sent: Tap,
    tap_received: Tap,
}

impl<L: ByteLink> Link<L> {
    /// A link in its generation, with a fresh session and nothing queued.
    pub fn new(
        io: L,
        role: Role,
        config: &Config<'_>,
        generation: u32,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            io,
            session: Session::new(role, config)?,
            framer: StreamFramer::new(),
            send: [0; FRAMED_BYTES],
            send_len: 0,
            sent: 0,
            stalls: 0,
            generation,
            closed: false,
            notices: [None; NOTICES],
            notice_head: 0,
            notice_len: 0,
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

    pub fn session(&self) -> &Session {
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

    /// Takes the oldest notice.
    pub fn next_notice(&mut self) -> Option<Notice> {
        if self.notice_len == 0 {
            return None;
        }
        let notice = self.notices.get_mut(self.notice_head)?.take();
        self.notice_head = (self.notice_head + 1) % NOTICES;
        self.notice_len -= 1;
        notice
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

    fn push_notice(&mut self, notice: Notice) {
        let at = (self.notice_head + self.notice_len) % NOTICES;
        if let Some(slot) = self.notices.get_mut(at) {
            *slot = Some(notice);
            self.notice_len += 1;
        }
    }

    fn notice_room(&self) -> bool {
        NOTICES - self.notice_len >= MAX_EVENTS
    }

    /// Frames `batch` into the send slot, which must be free.
    fn queue(&mut self, batch: &[u8]) -> Result<(), Error> {
        if self.send_len != 0 {
            return Err(Error::SendBusy);
        }
        let written = encode::stream_batch(&mut self.send, batch)?;
        self.tap_sent.keep(batch);
        self.send_len = written;
        self.sent = 0;
        Ok(())
    }

    /// Queues the connector's INIT_SYN.
    pub fn open(&mut self, handle: LinkHandle, now_ms: u64) -> Result<(), Error> {
        self.check(handle)?;
        let mut body = [0u8; MAX_BATCH_BYTES];
        let outcome = self.session.connect(now_ms, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Queues a PUSH carrying `payload` under `key`.
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
        let mut body = [0u8; MAX_BATCH_BYTES];
        let outcome = self.session.send_put(key, attachment, payload, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
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
        let mut body = [0u8; MAX_BATCH_BYTES];
        let outcome = self.session.send_declare_subscriber(id, key, &mut body)?;
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
        let mut body = [0u8; MAX_BATCH_BYTES];
        let outcome = self.session.send_undeclare_subscriber(id, key, &mut body)?;
        let batch = outcome.batch(&body);
        self.queue(batch)
    }

    /// Sends CLOSE and ends the link.
    pub fn close(&mut self, handle: LinkHandle, reason: u8) -> Result<(), Error> {
        self.check(handle)?;
        let mut body = [0u8; MAX_BATCH_BYTES];
        let outcome = self.session.close(reason, &mut body)?;
        self.absorb(&outcome);
        let batch = outcome.batch(&body);
        if self.send_len == 0 {
            self.queue(batch)?;
        }
        self.closed = true;
        Ok(())
    }

    fn absorb(&mut self, outcome: &crate::zenoh_profile0::session::Outcome<'_>) {
        for event in outcome.events.iter() {
            let notice = match *event {
                Event::HandshakeComplete => Notice::HandshakeComplete,
                Event::SubscriberDeclared { id } => Notice::SubscriberDeclared { id },
                Event::SubscriberUndeclared { id } => Notice::SubscriberUndeclared { id },
                Event::Closed { reason } => Notice::Closed { reason },
                Event::SampleDelivered {
                    sequence,
                    timestamp,
                    payload,
                } => {
                    let mut copy = [0u8; crate::zenoh_profile0::MAX_PAYLOAD_BYTES];
                    let len = payload.len().min(copy.len());
                    if let (Some(dst), Some(src)) = (copy.get_mut(..len), payload.get(..len)) {
                        dst.copy_from_slice(src);
                    }
                    Notice::SampleDelivered(Sample {
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
        let mut body = [0u8; MAX_BATCH_BYTES];
        if let Ok(outcome) = self.session.close(0, &mut body) {
            self.absorb(&outcome);
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

    /// Drives the link once: flush, read, decode and reply, then check the lease.
    pub fn pump(&mut self, handle: LinkHandle, now_ms: u64) -> Result<PumpReport, Error> {
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
        self.fill(&mut report)?;
        self.drain(now_ms, &mut report)?;
        if !self.closed {
            let mut body = [0u8; MAX_BATCH_BYTES];
            let outcome = self.session.tick(now_ms, &mut body)?;
            self.absorb(&outcome);
            if outcome.sent != 0 {
                let batch = outcome.batch(&body);
                if self.send_len == 0 {
                    self.queue(batch)?;
                }
                self.closed = true;
            }
        }
        report.sent_bytes += match self.flush() {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.fail(error)),
        };
        Ok(report)
    }

    /// Reads what the stream offers into the reassembly buffer. A full buffer
    /// while a batch still cannot be completed means the peer sent more than one
    /// batch can hold: that is refused, never dropped silently.
    fn fill(&mut self, report: &mut PumpReport) -> Result<(), Error> {
        loop {
            let room = FRAMED_BYTES - self.framer.pending();
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

    fn drain(&mut self, now_ms: u64, report: &mut PumpReport) -> Result<(), Error> {
        loop {
            if self.closed || self.send_len != 0 || !self.notice_room() {
                return Ok(());
            }
            let mut batch = [0u8; MAX_BATCH_BYTES];
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
            self.tap_received.keep(body);
            let mut reply = [0u8; MAX_BATCH_BYTES];
            let outcome = match self.session.on_batch(body, now_ms, &mut reply) {
                Ok(outcome) => outcome,
                Err(error) => return Err(self.fail(Error::Session(error))),
            };
            let observed = !outcome.events.is_empty();
            self.absorb(&outcome);
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
