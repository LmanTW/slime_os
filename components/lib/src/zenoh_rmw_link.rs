//! A Profile 0 graph link: one [`GraphSessionOf`] over a [`ByteLink`], feeding the liveliness tokens it
//! receives into a bounded [`Graph`].
//!
//! The plain link (`zenoh_link`) matches the plain session's `Event` exhaustively, and a graph session emits
//! none, so this is a separate type. It reuses the byte stream, the stream framer and the encoder, and repeats
//! the plain link's single send slot, its retry limit and its rule that a refusal ends the link.
//!
//! A token the graph refuses, or a token past the graph's capacity, is counted and dropped. The link does not
//! end: a graph entry is advice about the peer, and one unreadable token must not end a session that may carry
//! data. A refusal of the stream or of the session still ends the link, as it does for the plain link.
//! Every buffer is sized by const generics and nothing allocates.

use crate::zenoh_link::{ByteLink, LinkError, MAX_RETRIES, PumpReport};
use crate::zenoh_profile0::encode::{self, EncodeError};
use crate::zenoh_profile0::graph::{GraphError, GraphSessionOf, Kind as DeclKind};
use crate::zenoh_profile0::session::{Config, Params, Role, SessionError, State};
use crate::zenoh_profile0::{Refusal, STREAM_LENGTH_BYTES, StreamFramerOf};
use crate::zenoh_rmw_graph::Graph;

const READ_CHUNK: usize = 64;

/// Why the link refuses an operation or ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphLinkError {
    /// The byte stream failed.
    Link(LinkError),
    /// The stream carried a length prefix or a batch the profile refuses.
    Stream(Refusal),
    /// The graph session refused the batch or the request.
    Graph(GraphError),
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

impl GraphLinkError {
    /// The class name the exam pins.
    pub fn class(self) -> &'static str {
        match self {
            Self::Link(LinkError::Reset) => "link-reset",
            Self::Link(LinkError::Closed) => "link-closed",
            Self::Stream(refusal) => refusal.name(),
            Self::Graph(error) => error.class(),
            Self::Encode(_) => "encode",
            Self::RetryLimit => "retry-limit",
            Self::SendBusy => "send-busy",
            Self::ReceiveQueueFull => "receive-queue-full",
            Self::SendAfterClose => "send-after-close",
            Self::StaleHandle => "stale-handle",
        }
    }
}

impl From<GraphError> for GraphLinkError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

impl From<SessionError> for GraphLinkError {
    fn from(error: SessionError) -> Self {
        Self::Graph(GraphError::Session(error))
    }
}

impl From<EncodeError> for GraphLinkError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// Proof that a caller holds the link of one generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphHandle {
    generation: u32,
}

/// A graph link over a byte stream. `FRAMED` is the batch the link announces with its stream length, `A`
/// and `D` the aliases and declarations its session holds, `B` the longest key and `N` the entities its
/// graph holds.
pub struct GraphLinkOf<
    L: ByteLink,
    const FRAMED: usize,
    const A: usize,
    const D: usize,
    const B: usize,
    const N: usize,
> {
    io: L,
    session: GraphSessionOf<A, D, B>,
    graph: Graph<N>,
    framer: StreamFramerOf<FRAMED>,
    send: [u8; FRAMED],
    send_len: usize,
    sent: usize,
    stalls: u32,
    generation: u32,
    closed: bool,
    close_reason: Option<u8>,
    refused_tokens: u32,
}

impl<
    L: ByteLink,
    const FRAMED: usize,
    const A: usize,
    const D: usize,
    const B: usize,
    const N: usize,
> GraphLinkOf<L, FRAMED, A, D, B, N>
{
    /// A link in its generation, declared by `params`, whose graph serves `domain`.
    pub fn new(
        io: L,
        role: Role,
        config: &Config<'_>,
        params: Params,
        domain: u64,
        generation: u32,
    ) -> Result<Self, SessionError> {
        if params.bounds.batch + STREAM_LENGTH_BYTES != FRAMED {
            return Err(SessionError::InvalidConfig);
        }
        Ok(Self {
            io,
            session: GraphSessionOf::new(role, config, params)?,
            graph: Graph::new(domain),
            framer: StreamFramerOf::new(),
            send: [0; FRAMED],
            send_len: 0,
            sent: 0,
            stalls: 0,
            generation,
            closed: false,
            close_reason: None,
            refused_tokens: 0,
        })
    }

    pub const fn handle(&self) -> GraphHandle {
        GraphHandle {
            generation: self.generation,
        }
    }

    pub const fn graph(&self) -> &Graph<N> {
        &self.graph
    }

    pub const fn session(&self) -> &GraphSessionOf<A, D, B> {
        &self.session
    }

    pub fn io(&self) -> &L {
        &self.io
    }

    pub fn io_mut(&mut self) -> &mut L {
        &mut self.io
    }

    /// Tokens the graph refused or had no room for, dropped and counted.
    pub const fn refused_tokens(&self) -> u32 {
        self.refused_tokens
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Why the link ended: the reason of the peer's CLOSE, of a local close, `CLOSE_EXPIRED` when the lease
    /// ran out, or 0 when a stream or session refusal ended it. `None` while the link is open.
    pub const fn close_reason(&self) -> Option<u8> {
        self.close_reason
    }

    /// Whether a framed batch is waiting to be sent.
    pub const fn send_pending(&self) -> bool {
        self.send_len != 0
    }

    /// Whether the session finished its handshake and is still open.
    pub fn is_open(&self) -> bool {
        self.session.state() == State::Open && !self.closed
    }

    fn check(&self, handle: GraphHandle) -> Result<(), GraphLinkError> {
        if handle.generation != self.generation {
            return Err(GraphLinkError::StaleHandle);
        }
        if self.closed {
            return Err(GraphLinkError::SendAfterClose);
        }
        Ok(())
    }

    /// Frames `batch` into the send slot, which must be free.
    fn queue(&mut self, batch: &[u8]) -> Result<(), GraphLinkError> {
        if self.send_len != 0 {
            return Err(GraphLinkError::SendBusy);
        }
        let written =
            encode::stream_batch_max(&mut self.send, batch, FRAMED - STREAM_LENGTH_BYTES)?;
        self.send_len = written;
        self.sent = 0;
        Ok(())
    }

    /// Queues the connector's INIT_SYN.
    pub fn open(&mut self, handle: GraphHandle, now_ms: u64) -> Result<(), GraphLinkError> {
        self.check(handle)?;
        let mut body = [0u8; FRAMED];
        let outcome = self.session.connect(now_ms, &mut body)?;
        self.queue(outcome.batch(&body))
    }

    /// Queues CLOSE and ends the link. Refused with [`GraphLinkError::SendBusy`], changing nothing, while a
    /// batch is still waiting to be sent. The free slot is checked first, and a CLOSE is two bytes, so
    /// `queue` cannot then refuse it at any batch size the profile allows.
    pub fn close(&mut self, handle: GraphHandle, reason: u8) -> Result<(), GraphLinkError> {
        self.check(handle)?;
        if self.send_len != 0 {
            return Err(GraphLinkError::SendBusy);
        }
        let mut body = [0u8; FRAMED];
        let outcome = self.session.close(reason, &mut body)?;
        self.graph.clear();
        self.queue(outcome.batch(&body))?;
        self.closed = true;
        self.close_reason = Some(reason);
        Ok(())
    }

    /// Ends the link after a stream or session refusal that makes the rest of the stream untrustworthy.
    fn fail(&mut self, error: GraphLinkError) -> GraphLinkError {
        let mut body = [0u8; FRAMED];
        if let Ok(outcome) = self.session.close(0, &mut body) {
            let batch = outcome.batch(&body);
            if self.send_len == 0 {
                let _ = self.queue(batch);
            }
        }
        self.graph.clear();
        self.closed = true;
        self.close_reason = Some(0);
        error
    }

    fn flush(&mut self) -> Result<usize, GraphLinkError> {
        let mut total = 0;
        while self.send_len != 0 {
            let pending = self.send.get(self.sent..self.send_len).unwrap_or(&[]);
            let accepted = self.io.send(pending).map_err(GraphLinkError::Link)?;
            if accepted == 0 {
                self.stalls += 1;
                if self.stalls > MAX_RETRIES {
                    return Err(GraphLinkError::RetryLimit);
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
    ///
    /// One send slot holds one batch. When the lease runs out while the slot is occupied, the link ends and
    /// the graph is emptied, but the CLOSE is not written: only a free slot queues it. A refusal that ends
    /// the link has the same limit. The peer then finds out by its own lease. The plain link `zenoh_link`
    /// has the same limit today, and no test here holds that.
    pub fn pump(&mut self, handle: GraphHandle, now_ms: u64) -> Result<PumpReport, GraphLinkError> {
        if handle.generation != self.generation {
            return Err(GraphLinkError::StaleHandle);
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
        self.drain(now_ms, &mut report)?;
        if !self.closed {
            let mut body = [0u8; FRAMED];
            // The single send slot decides whether a keep-alive may be written at all: with a batch
            // waiting in it only the lease is checked, so a keep-alive never collides with that batch.
            let ticked = if self.send_len == 0 {
                self.session.tick(now_ms, &mut body)
            } else {
                self.session.tick_lease(now_ms, &mut body)
            };
            let outcome = match ticked {
                Ok(outcome) => outcome,
                Err(error) => return Err(self.fail(GraphLinkError::Graph(error))),
            };
            if outcome.sent != 0 && self.send_len == 0 {
                self.queue(outcome.batch(&body))?;
            }
            if let Some(reason) = outcome.closed {
                self.graph.clear();
                self.closed = true;
                self.close_reason = Some(reason);
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

    /// Reads what the stream offers into the reassembly buffer. A full buffer while a batch still cannot
    /// be completed means the peer sent more than one batch can hold: that is refused, never dropped.
    fn fill(&mut self, report: &mut PumpReport) -> Result<(), GraphLinkError> {
        loop {
            let room = FRAMED - self.framer.pending();
            if room == 0 {
                return match self.framer.peek_batch() {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err(self.fail(GraphLinkError::ReceiveQueueFull)),
                    Err(refusal) => Err(self.fail(GraphLinkError::Stream(refusal))),
                };
            }
            let mut chunk = [0u8; READ_CHUNK];
            let window = chunk.get_mut(..room.min(READ_CHUNK)).unwrap_or(&mut []);
            let read = match self.io.recv(window) {
                Ok(read) => read,
                Err(error) => return Err(self.fail(GraphLinkError::Link(error))),
            };
            if read == 0 {
                if self.io.eof() && self.framer.pending() == 0 {
                    return Err(self.fail(GraphLinkError::Link(LinkError::Closed)));
                }
                return Ok(());
            }
            let held = window.get(..read).unwrap_or(&[]);
            let taken = self.framer.push(held);
            report.received_bytes += taken;
            if let Err(refusal) = self.framer.peek_batch() {
                return Err(self.fail(GraphLinkError::Stream(refusal)));
            }
        }
    }

    fn drain(&mut self, now_ms: u64, report: &mut PumpReport) -> Result<(), GraphLinkError> {
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
                Err(refusal) => return Err(self.fail(GraphLinkError::Stream(refusal))),
            };
            let body = batch.get(..len).unwrap_or(&[]);
            let mut reply = [0u8; FRAMED];
            let graph = &mut self.graph;
            let refused = &mut self.refused_tokens;
            let applied = self
                .session
                .on_batch_visit(body, now_ms, &mut reply, &mut |change| {
                    if change.kind != DeclKind::Token {
                        return;
                    }
                    let outcome = match core::str::from_utf8(change.key) {
                        Ok(key) if change.declared => graph.declare(key).map(|_| ()),
                        Ok(key) => graph.withdraw(key),
                        Err(_) => Err(crate::zenoh_rmw_graph::GraphError::InvalidToken),
                    };
                    if outcome.is_err() {
                        *refused += 1;
                    }
                });
            let outcome = match applied {
                Ok(outcome) => outcome,
                Err(error) => return Err(self.fail(GraphLinkError::Graph(error))),
            };
            if let Some(reason) = outcome.closed {
                self.graph.clear();
                self.closed = true;
                self.close_reason = Some(reason);
            }
            self.framer.consume_batch();
            report.batches += 1;
            let sent = outcome.batch(&reply);
            if !sent.is_empty() {
                self.queue(sent)?;
            }
        }
    }
}

#[cfg(test)]
include!("zenoh_rmw_link/exam.rs");
