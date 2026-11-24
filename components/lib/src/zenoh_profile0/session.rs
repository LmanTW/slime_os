//! Zenoh Profile 0 session state machine.
//!
//! Pure: no I/O, no allocation and no clock. The caller feeds decoded batches
//! (or whole batch bodies) with the current time in milliseconds and sends the
//! batch body the machine writes into the storage it lends; the stream length
//! prefix is [`encode::stream_batch`]'s.
//!
//! A refused call leaves the session as it was, so a caller that wants the link
//! gone after a refusal must say so with [`Session::close`]. The only
//! transitions into [`State::Closed`] are a received CLOSE, a local close and
//! lease expiry. A KEEP_ALIVE is traffic on an open session and is sent every quarter of the
//! lease this side announced when nothing else was. The machine tracks the subscriptions of both sides in one
//! table: the ones this side declared, up to [`Params::local`], which a received PUSH must match to be
//! delivered, and the ones the peer declared, up to [`Params::per_side`], which a Put this side sends must
//! match.

use super::encode::{self, EncodeError, FrameEncoder};
use super::fragment::{
    Fragment, FragmentError, PutMessage, PutRules, Source, Splitter, decode_fragment, decode_put,
    fits_one_frame, is_fragment,
};
use super::lane::{Lane, decode_lane_fragment, decode_lane_frame, is_frame, peek_fragment_lane};
use super::lane_limits::MAX_RUNS_LIMIT;
use super::limits::{Limits, Mode};
use super::reassembly::{Progress, Run};
use super::tables::{InsertError, Keys, SlotTable};
use super::{
    Bounds, Frame, MAX_BATCH_BYTES, MAX_COOKIE_BYTES, MAX_KEY_BYTES, Mapping, Message, Network,
    Qos, QueryKey, Refusal, STREAM_LENGTH_BYTES, decode_batch_client, decode_batch_qos,
    decode_batch_with, frame_of,
};
use slime_proto::zenoh_profile as p;

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "lane_frames_tests.rs"]
mod lane_frames_tests;

#[cfg(test)]
#[path = "lanes_handshake_tests.rs"]
mod lanes_handshake_tests;

/// The liveliness tokens a session holds at once: a node, a publisher and a subscription each, and one to spare.
pub const MAX_TOKENS: usize = 4;
/// Events one received batch can yield; this is the contract's outstanding-sample bound.
pub const MAX_EVENTS: usize = 4;
/// The batch size the first release advertises in INIT.
const OUR_BATCH_SIZE: u16 = MAX_BATCH_BYTES as u16;
/// Table changes one FRAME may make before it is refused, so a frame that fails midway can be undone.
const JOURNAL: usize = 16;

/// What a session is declared with beyond its identity: the sizes it reads and writes, the batch it
/// announces, and whether it reassembles fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub bounds: Bounds,
    /// The batch announced in INIT, the stream length included.
    pub announced: u16,
    pub fragments: bool,
    pub timeout_ms: u64,
    /// The largest message one reassembly may join.
    pub message_limit: usize,
    /// Subscribers the peer may declare.
    pub per_side: usize,
    /// Subscriptions this side may declare, at least 1. The subscriber table holds `per_side + local`
    /// slots.
    pub local: usize,
    /// The most events one received batch can yield; the session's event storage must hold them.
    pub events: usize,
    /// The key aliases the peer may declare.
    pub aliases: usize,
    /// The samples the owner may hold unread; the link queues two notices for each.
    pub samples: usize,
    /// Whether this is the configuration of a [`graph::GraphSessionOf`]. A plain session refuses it: the
    /// declarations and extensions of an rmw_zenoh peer are taken by the graph session and nowhere else.
    pub graph: bool,
}

impl Params {
    /// The first release's: a fixed 512-byte batch.
    pub const DEMO: Self = Self {
        bounds: Bounds::DEMO,
        announced: OUR_BATCH_SIZE,
        fragments: false,
        timeout_ms: 0,
        message_limit: 0,
        per_side: 1,
        local: 1,
        events: MAX_EVENTS,
        aliases: 1,
        samples: MAX_EVENTS,
        graph: false,
    };

    /// The parameters a limits declaration describes.
    pub fn from_limits(limits: &Limits) -> Self {
        let body = limits.batch_bytes.saturating_sub(STREAM_LENGTH_BYTES);
        Self {
            bounds: Bounds {
                batch: body,
                key: limits.key_bytes,
                payload: usize::try_from(limits.payload_bytes).unwrap_or(usize::MAX),
            },
            announced: u16::try_from(limits.batch_bytes).unwrap_or(u16::MAX),
            fragments: limits.mode == Mode::Heap,
            timeout_ms: limits.reassembly_timeout_ms,
            message_limit: usize::try_from(limits.message_bytes()).unwrap_or(usize::MAX),
            per_side: limits.max_subscribers,
            local: 1,
            events: limits.events_per_batch(),
            aliases: limits.max_keys,
            samples: limits.outstanding_samples,
            graph: false,
        }
    }
}
const CLOSE_EXPIRED: u8 = p::CLOSE_EXPIRED as u8;
const ZID_BYTES: usize = p::MAX_ZID_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Connector,
    Listener,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Connector: before [`Session::connect`]. Listener: waiting for INIT_SYN.
    Idle,
    /// Connector: INIT_SYN sent.
    AwaitInitAck,
    /// Listener: INIT_ACK sent.
    AwaitOpenSyn,
    /// Connector: OPEN_SYN sent.
    AwaitOpenAck,
    Open,
    Closed,
}

/// Why the machine refuses a call. Every variant leaves the session unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The decoder refused the batch.
    Decode(Refusal),
    /// The encoder refused to build, or the lent storage was too small for, the reply.
    Encode(EncodeError),
    /// The [`Config`] cannot be sent on the wire.
    InvalidConfig,
    /// The session is closed.
    Closed,
    /// A send was asked for before the handshake finished.
    NotOpen,
    /// A message the current state and role do not accept, such as a FRAME before OPEN.
    UnexpectedMessage,
    /// OPEN_SYN echoed a cookie other than the one INIT_ACK carried.
    CookieMismatch,
    /// A reliable FRAME whose sequence number is not the next expected one.
    SequenceMismatch,
    /// A declaration while the single subscriber slot is occupied.
    SubscriberLimit,
    /// An undeclaration that does not name the declared subscriber.
    UnknownSubscriber,
    /// A PUSH whose key is not the declared subscriber's key.
    UndeclaredKey,
    /// A FRAME yielding more than [`MAX_EVENTS`] events, or changing more than the journal holds.
    TooManyMessages,
    /// A fragmented Put or a reassembly the fragment codec or the storage refused.
    Fragment(FragmentError),
    /// The storage lent for a reassembly cannot hold the message.
    OutOfMemory,
    /// A Put too large for one frame, which a session that fragments sends as fragments.
    NeedsFragments,
    /// A first fragment on a reliable lane while every run the session holds is open. A best-effort lane
    /// drops the fragment instead.
    LaneLimit,
    /// A queryable declared under an id already held, or one more than the session holds.
    QueryableLimit,
    /// The withdrawal of a queryable the peer never declared.
    UnknownQueryable,
    /// A request under an id already outstanding, or while one is.
    RequestLimit,
    /// A liveliness token with an id already declared, or one more than the session holds.
    TokenLimit,
    /// The withdrawal of a liveliness token that was never declared.
    UnknownToken,
}

impl SessionError {
    /// The class name the exams pin: the decoder's own, or the session's.
    pub fn class(self) -> &'static str {
        match self {
            Self::Decode(refusal) => refusal.name(),
            Self::Encode(_) => "encode",
            Self::InvalidConfig => "invalid-config",
            Self::Closed => "closed",
            Self::NotOpen => "not-open",
            Self::UnexpectedMessage => "unexpected-message",
            Self::CookieMismatch => "cookie-mismatch",
            Self::SequenceMismatch => "sequence-mismatch",
            Self::SubscriberLimit => "subscriber-limit",
            Self::UnknownSubscriber => "unknown-subscriber",
            Self::UndeclaredKey => "undeclared-key",
            Self::TooManyMessages => "too-many-messages",
            Self::Fragment(error) => error.class(),
            Self::OutOfMemory => "out-of-memory",
            Self::NeedsFragments => "needs-fragments",
            Self::LaneLimit => "lane-limit",
            Self::QueryableLimit => "queryable-limit",
            Self::UnknownQueryable => "unknown-queryable",
            Self::RequestLimit => "request-limit",
            Self::TokenLimit => "token-limit",
            Self::UnknownToken => "unknown-token",
        }
    }
}

impl From<Refusal> for SessionError {
    fn from(refusal: Refusal) -> Self {
        Self::Decode(refusal)
    }
}

impl From<FragmentError> for SessionError {
    fn from(error: FragmentError) -> Self {
        match error {
            FragmentError::Refused(refusal) => Self::Decode(refusal),
            FragmentError::SequenceMismatch => Self::SequenceMismatch,
            FragmentError::UndeclaredKey => Self::UndeclaredKey,
            FragmentError::OutOfMemory => Self::OutOfMemory,
            other => Self::Fragment(other),
        }
    }
}

impl From<EncodeError> for SessionError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// What a session reports to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    HandshakeComplete,
    SubscriberDeclared {
        id: u32,
    },
    /// A Put delivered to the declared key; `payload` borrows from the input batch.
    SampleDelivered {
        /// The id of the subscription this side declared on the key, which matched the Put.
        subscription: u32,
        sequence: i64,
        timestamp: i64,
        payload: &'a [u8],
    },
    SubscriberUndeclared {
        id: u32,
    },
    /// A fragmented Put joined into the lent storage: its payload is `len` bytes at the end of the
    /// `offset + len` bytes the storage holds.
    SampleStored {
        sequence: i64,
        timestamp: i64,
        offset: usize,
        len: usize,
    },
    Closed {
        reason: u8,
    },
    /// The peer declared a queryable on a key this side knows.
    QueryableDeclared {
        id: u32,
    },
    QueryableUndeclared {
        id: u32,
    },
    /// The peer asked one query. `request` is its id, which each response and the final response repeat.
    QueryReceived {
        request: u32,
        timeout_ms: u32,
    },
    /// The peer answered this side's query with one payload.
    ReplyDelivered {
        request: u32,
        payload: &'a [u8],
    },
    /// The peer ended the replies to this side's query.
    QueryFinished {
        request: u32,
    },
    /// A best-effort frame or run the session did not take. The lane stays open, and the loss is the
    /// owner's to count. A reliable lane refuses instead.
    Dropped {
        priority: u8,
        cause: DropCause,
    },
}

/// Why a best-effort lane dropped what it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropCause {
    /// The sequence number is not ahead of the last one taken, by less than 2^31.
    StaleSequence,
    /// A FRAME arrived on a lane with a run open, which ends the run.
    FrameDuringRun,
    /// A fragment arrived out of order, or the first one of a run was lost.
    FragmentSequence,
    /// A fragment of a run that already broke, discarded through its final fragment.
    Discarded,
    /// A first fragment with no free run.
    LaneLimit,
    /// A run that outlived its timeout.
    ReassemblyTimeout,
    /// A message that was taken and then refused. The class is the one a reliable lane returns.
    Completed(&'static str),
}

impl DropCause {
    /// The cause as the exam spells it, `completed` without its class.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StaleSequence => "stale-sequence",
            Self::FrameDuringRun => "frame-during-run",
            Self::FragmentSequence => "fragment-sequence",
            Self::Discarded => "discarded",
            Self::LaneLimit => "lane-limit",
            Self::ReassemblyTimeout => "reassembly-timeout",
            Self::Completed(_) => "completed",
        }
    }
}

/// Up to `E` events, in the order they happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Events<'a, const E: usize = MAX_EVENTS> {
    items: [Option<Event<'a>>; E],
    len: usize,
}

impl<'a, const E: usize> Events<'a, E> {
    const fn empty() -> Self {
        Self {
            items: [None; E],
            len: 0,
        }
    }

    fn push(&mut self, event: Event<'a>) -> Result<(), SessionError> {
        let slot = self
            .items
            .get_mut(self.len)
            .ok_or(SessionError::TooManyMessages)?;
        *slot = Some(event);
        self.len += 1;
        Ok(())
    }

    /// Adds a report that is the owner's to count: a drop. It takes a free slot and never displaces what the
    /// session delivered, so a full list loses the report and not the message.
    fn note(&mut self, event: Event<'a>) {
        let _ = self.push(event);
    }

    /// Adds a report ahead of the events that follow it, when a slot is free.
    fn note_first(&mut self, event: Event<'a>) {
        if self.len >= E {
            return;
        }
        self.items.copy_within(0..self.len, 1);
        self.items[0] = Some(event);
        self.len += 1;
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<&Event<'a>> {
        self.items.get(index)?.as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Event<'a>> {
        self.items.iter().flatten()
    }
}

/// The result of one accepted call: the batch body written, if any, and events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome<'a, const E: usize = MAX_EVENTS> {
    /// Length of the batch body written at the start of the lent storage; 0 means nothing to send.
    pub sent: usize,
    pub events: Events<'a, E>,
}

impl<'a, const E: usize> Outcome<'a, E> {
    const fn nothing() -> Self {
        Self {
            sent: 0,
            events: Events::empty(),
        }
    }

    const fn sending(sent: usize) -> Self {
        Self {
            sent,
            events: Events::empty(),
        }
    }

    fn with(mut self, event: Event<'a>) -> Self {
        // An empty `Events` has room for one event, so the push cannot fail.
        let _ = self.events.push(event);
        self
    }

    /// The batch body written into `out`, empty when nothing was sent.
    pub fn batch<'b>(&self, out: &'b [u8]) -> &'b [u8] {
        out.get(..self.sent).unwrap_or(&[])
    }
}

/// Parameters a session announces. `cookie` is used by a listener only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config<'a> {
    /// 1 to 16 bytes.
    pub zid: &'a [u8],
    /// The silence after which this side closes; it is announced to the peer.
    pub lease_ms: u64,
    /// The sequence number of this side's first reliable FRAME.
    pub initial_sn: u32,
    /// 1 to 64 bytes.
    pub cookie: &'a [u8],
}

/// A table change a FRAME made, so a frame that fails midway can be undone.
#[derive(Clone, Copy, Debug)]
enum Change {
    Alias(usize),
    Subscribed(usize),
    Unsubscribed(usize),
    /// The query state before the message that changed it, restored whole.
    Queries(Queries),
}

/// What a session holds about queries, by id and key: the queryable the peer declared, the request the peer asked
/// and has not had finished, and the request this side asked and has not had finished. Each holds at most one,
/// because a link carries one query at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Queries {
    peer_queryable: Option<u32>,
    peer_request: Option<u32>,
    own_request: Option<u32>,
    /// The queryable this side declared, and the alias of its key. A received frame never changes them.
    own_queryable: Option<u32>,
    own_alias: u32,
}

/// The alias a reference names, or the refusal a reference to an alias nobody declared draws. The alias
/// resolves to the declared key and no other. The peer declared it, so it lives in the sender's mapping;
/// a reference in the receiver's mapping names an alias this side declared, and this side declares none.
fn resolve<const K: usize, const B: usize>(
    aliases: &SlotTable<K, B>,
    named: u32,
    mapping: Mapping,
) -> Result<&[u8], SessionError> {
    match aliases.key_of(u64::from(named)) {
        Some(key) if mapping == Mapping::Sender => Ok(key),
        _ => Err(SessionError::Decode(Refusal::InvalidKeyexpr)),
    }
}

fn same(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn put_byte(out: &mut [u8], at: &mut usize, byte: u8) -> Result<(), SessionError> {
    *out.get_mut(*at).ok_or(EncodeError::OutputTooSmall)? = byte;
    *at += 1;
    Ok(())
}

fn put_leb(out: &mut [u8], at: &mut usize, mut value: u32) -> Result<(), SessionError> {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            return put_byte(out, at, low);
        }
        put_byte(out, at, low | 0x80)?;
    }
}

/// What a table that would not take a slot means: `full` for a table with no room.
fn table_error(error: InsertError, full: SessionError) -> SessionError {
    match error {
        InsertError::Full => full,
        InsertError::Duplicate => SessionError::Decode(Refusal::InvalidKeyexpr),
        InsertError::KeyTooLong => SessionError::Decode(Refusal::OverBound),
    }
}

/// Delivers a Put to this side's subscriber when it names a key one of them declared.
fn deliver<'a, const S: usize, const B: usize, const E: usize>(
    subs: &SlotTable<S, B>,
    key: &[u8],
    attachment: crate::zenoh_profile0::Attachment<'a>,
    payload: &'a [u8],
    events: &mut Events<'a, E>,
) -> Result<(), SessionError> {
    let Some(subscription) = subscription_on(subs, key) else {
        return Err(SessionError::UndeclaredKey);
    };
    events.push(Event::SampleDelivered {
        subscription,
        sequence: attachment.sequence,
        timestamp: attachment.timestamp,
        payload,
    })
}

/// The tag on the id of a subscription this side declared; the peer's carry none.
const LOCAL: u64 = 1 << 32;

/// The id of the first subscription this side declared on `key`, if any.
fn subscription_on<const S: usize, const B: usize>(
    subs: &SlotTable<S, B>,
    key: &[u8],
) -> Option<u32> {
    let at = subs.find_by(|id, held| id & LOCAL != 0 && held == key)?;
    subs.get(at).map(|(id, _)| (id & !LOCAL) as u32)
}

/// Whether this side subscribed to `key`.
fn subscribed_to<const S: usize, const B: usize>(subs: &SlotTable<S, B>, key: &[u8]) -> bool {
    subscription_on(subs, key).is_some()
}

/// A session over `K` key aliases and `S` subscribers of each side, keys of up to `B` bytes. The
/// defaults are the first release's. `R` is the reassembly runs the session is built to hold. It is 1 for
/// every session written without it, and nothing reads it yet.
#[derive(Clone, Debug)]
pub struct SessionOf<
    const K: usize = 1,
    const S: usize = 2,
    const B: usize = MAX_KEY_BYTES,
    const E: usize = MAX_EVENTS,
    const R: usize = 1,
> {
    role: Role,
    state: State,
    params: Params,
    zid: [u8; ZID_BYTES],
    zid_len: usize,
    lease_ms: u64,
    peer_lease_ms: u64,
    tx_sn: u32,
    cookie: [u8; MAX_COOKIE_BYTES],
    cookie_len: usize,
    last_rx_ms: u64,
    /// When this side last sent a batch, or entered the handshake; keep-alives are due a quarter
    /// of this side's announced lease after it.
    last_tx_ms: u64,
    /// The latest time an accepted call gave the session. A send that has no clock of its own is
    /// stamped with it, and the link ticks the session on every pump.
    now_ms: u64,
    /// The batch the peer announced in its INIT; what this side sends is bounded by it.
    peer_batch: usize,
    /// The reassembly runs this side holds. 2 or more offers the QoS unit extension on its INIT.
    runs: usize,
    /// The peer's INIT carried the QoS unit extension.
    peer_qos: bool,
    /// The next sequence number each lane takes, indexed by [`Lane::index`], and whether the peer's OPEN has
    /// set it. A lane the peer has not used counts from the number its OPEN announced.
    lane_sn: [u32; LANES],
    /// One run for each of the `R` the session holds, and the lane each open run serves.
    run_table: [Run; R],
    run_lane: [Lane; R],
    /// Whether a best-effort lane drops fragments through its next final one, because its run broke.
    discarding: [bool; LANES],
    /// The key aliases a stock peer declared with DeclareKeyExpr, and the keys they stand for.
    aliases: SlotTable<K, B>,
    /// Every subscription, this side's and the peer's, in the `S` slots the configuration declares. A
    /// received PUSH is delivered only to the keys of this side's, and a Put this side sends must name
    /// one of the peer's.
    subs: SlotTable<S, B>,
    /// How many of `subs` each side holds, so a side's limit is checked without a scan.
    local_n: usize,
    remote_n: usize,
    /// This connector announces itself as a client and takes the INIT_ACK of a router.
    client: bool,
    /// The ids of the liveliness tokens this side declared and has not withdrawn. A withdrawal names the id and no key.
    tokens: [u32; MAX_TOKENS],
    token_n: usize,
    queries: Queries,
}

/// The lanes a session counts: a priority (0 to 7) and a reliability.
const LANES: usize = 16;
/// The default lane, which a plain FRAME and a FRAGMENT count on. A session has no other receive counter.
const DEFAULT_LANE: usize = Lane::DEFAULT.index();
/// A best-effort sequence number is ahead of the last one taken by less than half the 32-bit range.
const HALF: u32 = 1 << 31;

/// The events and samples one FRAME can raise, at most `E`.
fn count_events<const E: usize>(frame: &Frame<'_>) -> (usize, usize) {
    let mut events = 0;
    let mut samples = 0;
    for network in frame.messages() {
        match network {
            Network::PushPut { .. } | Network::PushPutAlias { .. } => {
                events += 1;
                samples += 1;
            }
            Network::DeclareSubscriber { .. }
            | Network::DeclareSubscriberAlias { .. }
            | Network::UndeclareSubscriber { .. }
            | Network::UndeclareSubscriberById { .. }
            | Network::DeclareQueryable { .. }
            | Network::UndeclareQueryable { .. }
            | Network::Request { .. }
            | Network::Response { .. }
            | Network::ResponseFinal { .. } => events += 1,
            _ => {}
        }
    }
    (events.min(E), samples.min(E))
}

/// The first release's session.
pub type Session = SessionOf<1, 2, MAX_KEY_BYTES, MAX_EVENTS>;

impl<const K: usize, const S: usize, const B: usize, const E: usize, const R: usize>
    SessionOf<K, S, B, E, R>
{
    /// A session with the first release's parameters, in [`State::Idle`], or
    /// [`SessionError::InvalidConfig`] when the encoder could not announce `config`.
    pub fn new(role: Role, config: &Config<'_>) -> Result<Self, SessionError> {
        Self::with_params(role, config, Params::DEMO)
    }

    /// A session declared by `params`, holding one reassembly run. It writes the INIT it always wrote.
    pub fn with_params(
        role: Role,
        config: &Config<'_>,
        params: Params,
    ) -> Result<Self, SessionError> {
        Self::with_lanes(role, config, params, 1)
    }

    /// A session declared by `params` that holds `runs` reassembly runs, at most [`MAX_RUNS_LIMIT`]. With 2
    /// or more it offers the QoS unit extension on its INIT, and a peer that offers it too makes the
    /// lanes hold ([`Self::lanes`]). With fewer it writes and reads the INIT of a session with one run.
    pub fn with_lanes(
        role: Role,
        config: &Config<'_>,
        params: Params,
        runs: usize,
    ) -> Result<Self, SessionError> {
        // The table is exactly what the type declares: fewer runs than `R` leaves slots the session does not
        // admit to, and more has nowhere to go. A fixed link holds none, as the limits contract states, and a
        // link that fragments needs at least one to join a message in.
        if runs != R || R > MAX_RUNS_LIMIT || (params.fragments && R == 0) {
            return Err(SessionError::InvalidConfig);
        }
        // The storage is exactly what the configuration declares: the peer's aliases, our own subscriptions
        // and the peer's, the key length and the events a batch yields. Smaller refuses what the limits
        // promise and larger leaves a bound that only the array enforces. A side that may declare none
        // cannot be a subscriber, so `local` is at least 1.
        if params.graph
            || params.bounds.key != B
            || params.events != E
            || params.aliases != K
            || params.local < 1
            || params.per_side.checked_add(params.local) != Some(S)
        {
            return Err(SessionError::InvalidConfig);
        }
        let mut scratch = [0u8; 2 * MAX_BATCH_BYTES];
        encode::init_syn_qos(&mut scratch, config.zid, params.announced)
            .map_err(|_| SessionError::InvalidConfig)?;
        encode::open_ack(&mut scratch, config.lease_ms, config.initial_sn)
            .map_err(|_| SessionError::InvalidConfig)?;
        let mut zid = [0u8; ZID_BYTES];
        let mut cookie = [0u8; MAX_COOKIE_BYTES];
        let mut cookie_len = 0;
        zid.get_mut(..config.zid.len())
            .ok_or(SessionError::InvalidConfig)?
            .copy_from_slice(config.zid);
        if role == Role::Listener {
            encode::init_ack_qos(&mut scratch, config.zid, params.announced, config.cookie)
                .map_err(|_| SessionError::InvalidConfig)?;
            cookie
                .get_mut(..config.cookie.len())
                .ok_or(SessionError::InvalidConfig)?
                .copy_from_slice(config.cookie);
            cookie_len = config.cookie.len();
        }
        Ok(Self {
            role,
            state: State::Idle,
            params,
            zid,
            zid_len: config.zid.len(),
            lease_ms: config.lease_ms,
            peer_lease_ms: 0,
            tx_sn: config.initial_sn,
            cookie,
            cookie_len,
            last_rx_ms: 0,
            last_tx_ms: 0,
            now_ms: 0,
            peer_batch: usize::from(u16::MAX),
            runs,
            peer_qos: false,
            lane_sn: [0; LANES],
            run_table: [Run::new(); R],
            run_lane: [Lane::DEFAULT; R],
            discarding: [false; LANES],
            aliases: SlotTable::new(),
            subs: SlotTable::new(),
            local_n: 0,
            remote_n: 0,
            client: false,
            tokens: [0; MAX_TOKENS],
            token_n: 0,
            queries: Queries::default(),
        })
    }

    /// The same session with the client role: its INIT_SYN carries `whatami` 2, and it takes an INIT_ACK of
    /// `whatami` 0 and refuses any other. Only a connector that has written nothing takes the role, because a
    /// listener never writes an INIT_SYN and a connector that has begun a handshake already announced itself.
    pub fn with_client_role(mut self) -> Result<Self, SessionError> {
        if self.role != Role::Connector || self.state != State::Idle {
            return Err(SessionError::InvalidConfig);
        }
        self.client = true;
        Ok(self)
    }

    /// Whether this session has the client role.
    pub const fn is_client(&self) -> bool {
        self.client
    }

    /// The next sequence number `lane` takes. A lane the peer has not used counts from the number its OPEN
    /// announced.
    pub const fn lane_next(&self, lane: Lane) -> u32 {
        self.lane_sn[lane.index()]
    }

    /// Whether this side offers the QoS unit extension on its INIT: it holds 2 or more runs.
    const fn offers_qos(&self) -> bool {
        self.runs >= 2
    }

    /// The reassembly runs this side holds.
    pub const fn runs(&self) -> usize {
        self.runs
    }

    /// Whether both INITs carried the QoS unit extension. Only then may a peer select a priority, so a
    /// side that offered nothing, or a peer that did not, has one lane.
    pub const fn lanes(&self) -> bool {
        self.offers_qos() && self.peer_qos
    }

    /// A graph session's check before it applies a FRAME: the session is open and `sn` is the next
    /// sequence number. The frame itself is applied by the graph session, which owns its tables.
    pub(super) fn graph_frame_expected(&self, sn: u32) -> Result<(), SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        if sn != self.lane_sn[DEFAULT_LANE] {
            return Err(SessionError::SequenceMismatch);
        }
        Ok(())
    }

    /// A graph session's commit after it applied a FRAME whole: the sequence number advances and the
    /// frame renews the lease. It stamps the clock as `on_batch_with` does for a plain session's accepted
    /// FRAME, without a `max`: only `tick` keeps the latest time a call gave the session.
    pub(super) fn graph_frame_accepted(&mut self, now_ms: u64) {
        self.lane_sn[DEFAULT_LANE] = self.lane_sn[DEFAULT_LANE].wrapping_add(1);
        self.last_rx_ms = now_ms;
        self.now_ms = now_ms;
    }

    /// A graph session's Put on a key the peer declared a subscriber for. The graph session holds the
    /// peer's subscribers and has checked the key, so this checks only what the plain `send_put` checks
    /// of the Put itself: the attachment, the payload bound and one FRAME.
    pub(super) fn graph_send_put<'a>(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if payload.len() > self.params.bounds.payload {
            return Err(SessionError::Decode(Refusal::OverBound));
        }
        encode::validate_put(key, attachment, payload.len(), &self.params.bounds)?;
        if self.state == State::Open && !self.put_fits_one_frame(key, attachment, payload.len()) {
            return Err(SessionError::Decode(Refusal::OverBound));
        }
        self.send_frame(out, |frame| {
            frame.push_put(Mapping::Sender, key, attachment, payload)
        })
    }

    /// A graph session's answer to an INTEREST: one reliable FRAME holding a DECLARE with the interest
    /// flag, the interest id and a DeclareFinal. `FrameEncoder` writes no such message, so the bytes are
    /// written here. The sequence number is spent only when the frame was built.
    pub(super) fn graph_send_final<'a>(
        &mut self,
        interest: u32,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        let mut at = 0;
        put_byte(out, &mut at, p::ID_FRAME as u8 | p::FLAG_BIT5 as u8)?;
        put_leb(out, &mut at, self.tx_sn)?;
        put_byte(out, &mut at, p::ID_DECLARE as u8 | p::FLAG_BIT5 as u8)?;
        put_leb(out, &mut at, interest)?;
        put_byte(out, &mut at, p::ID_DECLARE_FINAL as u8)?;
        if at > self.send_body_max() {
            return Err(EncodeError::BatchTooLarge.into());
        }
        self.tx_sn = self.tx_sn.wrapping_add(1);
        // The FRAME that asked for the answer is being applied at `now_ms`, and the clock is stamped when
        // it is committed, so the answer restarts the keep-alive from this time and not the previous one.
        self.sent_now(now_ms);
        Ok(Outcome::sending(at))
    }

    pub const fn role(&self) -> Role {
        self.role
    }

    pub const fn state(&self) -> State {
        self.state
    }

    pub const fn is_open(&self) -> bool {
        matches!(self.state, State::Open)
    }

    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// The sequence number the next reliable FRAME this side sends carries.
    pub const fn next_tx_sn(&self) -> u32 {
        self.tx_sn
    }

    /// The sequence number the next received reliable FRAME must carry; meaningful once open.
    pub const fn expected_rx_sn(&self) -> u32 {
        self.lane_sn[DEFAULT_LANE]
    }

    /// The lease the peer announced, 0 until the handshake completes.
    pub const fn peer_lease_ms(&self) -> u64 {
        self.peer_lease_ms
    }

    /// The batch the peer announced, 65535 until its INIT arrives or when it omitted the size.
    pub const fn peer_batch(&self) -> usize {
        self.peer_batch
    }

    /// The longest batch body this side sends: the smaller of its own batch and the peer's, less the
    /// stream length. The peer accepts no more, and this side's send storage holds no more.
    pub fn send_body_max(&self) -> usize {
        self.params
            .bounds
            .batch
            .min(self.peer_batch.saturating_sub(STREAM_LENGTH_BYTES))
    }

    /// Whether any run is open.
    pub fn reassembling(&self) -> bool {
        self.run_table.iter().any(Run::is_open)
    }

    /// The slot of the open run of `lane`, if it has one.
    fn slot_of(&self, lane: Lane) -> Option<usize> {
        self.run_table
            .iter()
            .zip(&self.run_lane)
            .position(|(run, held)| run.is_open() && *held == lane)
    }

    fn free_slot(&self) -> Option<usize> {
        self.run_table.iter().position(|run| !run.is_open())
    }

    /// The slot the next fragment of `lane` joins: the slot of its open run, or the first free one when it has
    /// none, or `None` when every run is open. The caller lends the storage of that slot to
    /// [`Self::on_lane_fragment`]. Nothing changes between the two calls, so the slot is the one the fragment
    /// takes.
    pub fn run_slot(&self, lane: Lane) -> Option<usize> {
        self.slot_of(lane).or_else(|| self.free_slot())
    }

    /// Whether the run in `slot` is open. A slot [`Self::run_slot`] names is open when its lane has a message in
    /// progress, and free when the fragment would start one.
    pub fn run_open(&self, slot: usize) -> bool {
        self.run_table.get(slot).is_some_and(Run::is_open)
    }

    /// The key aliases the peer declared.
    pub const fn aliases(&self) -> usize {
        self.aliases.len()
    }

    /// The subscribers held, of both sides.
    pub const fn subscribers(&self) -> usize {
        self.local_n + self.remote_n
    }

    fn first_of(&self, side: u64) -> Option<(u32, &[u8])> {
        let at = self.subs.find_by(|id, _| id & LOCAL == side)?;
        let (id, key) = self.subs.get(at)?;
        Some((id as u32, key))
    }

    /// The id of the subscriber this side declared, if any.
    pub fn subscriber_id(&self) -> Option<u32> {
        self.first_of(LOCAL).map(|(id, _)| id)
    }

    /// The key of the subscriber this side declared, if any.
    pub fn subscriber_key(&self) -> Option<&str> {
        core::str::from_utf8(self.first_of(LOCAL)?.1).ok()
    }

    /// The id of the subscriber the peer declared, if any.
    pub fn peer_subscriber_id(&self) -> Option<u32> {
        self.first_of(0).map(|(id, _)| id)
    }

    /// The key of the subscriber the peer declared, if any.
    pub fn peer_subscriber_key(&self) -> Option<&str> {
        core::str::from_utf8(self.first_of(0)?.1).ok()
    }

    /// The time after which [`tick`](Self::tick) closes the session; `None`
    /// while idle or closed.
    pub fn lease_deadline(&self) -> Option<u64> {
        match self.state {
            State::Idle | State::Closed => None,
            _ => Some(self.last_rx_ms.saturating_add(self.rx_lease_ms())),
        }
    }

    /// The peer's announced lease bounds the silence we tolerate once open; our
    /// own bounds the handshake.
    const fn rx_lease_ms(&self) -> u64 {
        if self.peer_lease_ms == 0 {
            self.lease_ms
        } else {
            self.peer_lease_ms
        }
    }

    fn own_zid(&self) -> Result<&[u8], SessionError> {
        self.zid
            .get(..self.zid_len)
            .ok_or(SessionError::InvalidConfig)
    }

    fn own_cookie(&self) -> Result<&[u8], SessionError> {
        self.cookie
            .get(..self.cookie_len)
            .ok_or(SessionError::InvalidConfig)
    }

    fn shut(&mut self) {
        self.state = State::Closed;
        self.subs.clear();
        self.local_n = 0;
        self.remote_n = 0;
        self.token_n = 0;
        self.queries = Queries::default();
        self.aliases.clear();
        for run in &mut self.run_table {
            run.release();
        }
        self.discarding = [false; LANES];
    }

    /// Stamps a batch this side sent, which restarts the keep-alive cadence.
    fn sent_now(&mut self, now_ms: u64) {
        self.last_tx_ms = now_ms;
    }

    /// Tells the session a batch reached the wire at `now_ms`, which restarts the keep-alive
    /// cadence from that moment. A call that builds a frame has no clock and stamps the latest time
    /// the session was given, which can be earlier than the flush; the link that owns the send slot
    /// knows the real time.
    pub fn note_sent(&mut self, now_ms: u64) {
        self.now_ms = self.now_ms.max(now_ms);
        self.last_tx_ms = self.last_tx_ms.max(now_ms);
    }

    /// Connector only: writes INIT_SYN and starts waiting for INIT_ACK.
    pub fn connect<'a>(
        &mut self,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.role != Role::Connector || self.state != State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        let (zid, announced) = (self.own_zid()?, self.params.announced);
        let sent = match (self.client, self.offers_qos()) {
            (true, true) => encode::init_syn_client_qos(out, zid, announced)?,
            (true, false) => encode::init_syn_client(out, zid, announced)?,
            (false, true) => encode::init_syn_qos(out, zid, announced)?,
            (false, false) => encode::init_syn(out, zid, announced)?,
        };
        self.state = State::AwaitInitAck;
        self.last_rx_ms = now_ms;
        self.last_tx_ms = now_ms;
        self.now_ms = now_ms;
        Ok(Outcome::sending(sent))
    }

    /// Decodes `batch` (a body without its stream prefix) and applies it. A session that reassembles
    /// has no storage here, so a fragment is refused as out of memory; see
    /// [`on_batch_with`](Self::on_batch_with).
    pub fn on_batch<'a>(
        &mut self,
        batch: &'a [u8],
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        self.on_batch_with(batch, now_ms, out, &mut [])
    }

    /// Decodes `batch` and applies it. `cell` is the storage a fragmented message is joined into; the
    /// caller keeps lending the same cell until a message completes, and the sample it yields is the
    /// `SampleStored` range of it.
    pub fn on_batch_with<'a>(
        &mut self,
        batch: &'a [u8],
        now_ms: u64,
        out: &mut [u8],
        cell: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        if self.params.fragments && batch.first().copied().is_some_and(is_fragment) {
            // A session that negotiated lanes takes its fragments through `on_lane_fragment`, which names the
            // storage of the run. One lent cell cannot serve several runs.
            if self.lanes() {
                return Err(SessionError::UnexpectedMessage);
            }
            let outcome = self.on_fragment(batch, now_ms, cell)?;
            self.last_rx_ms = now_ms;
            self.now_ms = now_ms;
            return Ok(outcome);
        }
        if self.lanes() && !self.client && batch.first().copied().is_some_and(is_frame) {
            return self.on_lane_frame(batch, now_ms);
        }
        let message = self.decode(batch)?;
        self.on_message(message, now_ms, out)
    }

    /// Decodes `batch` as this session reads it: with the client role, an INIT_ACK of a router is taken.
    fn decode<'a>(&self, batch: &'a [u8]) -> Result<Message<'a>, Refusal> {
        if self.client {
            decode_batch_client(batch, &self.params.bounds, self.offers_qos())
        } else if self.offers_qos() {
            decode_batch_qos(batch, &self.params.bounds)
        } else {
            decode_batch_with(batch, &self.params.bounds)
        }
    }

    /// What a received batch can raise, judged without applying it so a link can wait until its queue
    /// and heap have room: the most notices, and how many of them are samples. A batch the decoder
    /// refuses raises none, and one that raises more than the session's events can hold is reported at
    /// the cap, so the session, not the link, refuses it and names the cause.
    pub fn events_needed(&self, batch: &[u8]) -> (usize, usize) {
        if self.params.fragments && batch.first().copied().is_some_and(is_fragment) {
            let last = batch.first().is_some_and(|header| header & 0x40 == 0);
            return (usize::from(last), usize::from(last));
        }
        // A FRAME on a negotiated link is read by its lane. A best-effort FRAME the lane drops raises one event
        // and no sample, and the estimate of a FRAME that delivers is the larger of the two, so the room it
        // asks for covers both.
        if self.lanes() && !self.client && batch.first().copied().is_some_and(is_frame) {
            return match decode_lane_frame(batch) {
                Ok(header) => {
                    let dropped = usize::from(!header.lane.reliable);
                    match frame_of(header.sn, header.body, &self.params.bounds, false) {
                        Ok(frame) => {
                            let (events, samples) = count_events::<E>(&frame);
                            (events.max(dropped), samples)
                        }
                        Err(_) => (dropped, 0),
                    }
                }
                Err(_) => (0, 0),
            };
        }
        match self.decode(batch) {
            Ok(Message::Frame(frame)) => count_events::<E>(&frame),
            Ok(Message::OpenSyn { .. } | Message::OpenAck { .. } | Message::Close { .. }) => (1, 0),
            _ => (0, 0),
        }
    }

    /// Applies one decoded message. An accepted message refreshes the lease.
    pub fn on_message<'a>(
        &mut self,
        message: Message<'a>,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        let outcome = match message {
            Message::InitSyn {
                batch_size, qos, ..
            } => self.on_init_syn(batch_size, qos, out)?,
            Message::InitAck {
                cookie,
                batch_size,
                qos,
                ..
            } => self.on_init_ack(cookie, batch_size, qos, out)?,
            Message::OpenSyn {
                lease_ms,
                initial_sn,
                cookie,
            } => self.on_open_syn(lease_ms, initial_sn, cookie, out)?,
            Message::OpenAck {
                lease_ms,
                initial_sn,
            } => self.on_open_ack(lease_ms, initial_sn)?,
            Message::Close { reason, .. } => self.on_close(reason)?,
            Message::KeepAlive => self.on_keep_alive()?,
            Message::Frame(frame) => self.on_frame(frame)?,
        };
        self.last_rx_ms = now_ms;
        self.now_ms = now_ms;
        if outcome.sent != 0 {
            self.sent_now(now_ms);
        }
        Ok(outcome)
    }

    fn on_init_syn<'a>(
        &mut self,
        batch_size: u16,
        qos: bool,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.role != Role::Listener || self.state != State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        // The extension answers an offer. A listener that offers nothing, or a peer that offered nothing,
        // gets the INIT_ACK a session with one run writes.
        let sent = if self.offers_qos() && qos {
            encode::init_ack_qos(
                out,
                self.own_zid()?,
                self.params.announced,
                self.own_cookie()?,
            )?
        } else {
            encode::init_ack(
                out,
                self.own_zid()?,
                self.params.announced,
                self.own_cookie()?,
            )?
        };
        // The reply is a batch and cannot be fragmented: the peer must have said it accepts it, stream
        // length included.
        if sent + STREAM_LENGTH_BYTES > usize::from(batch_size) {
            return Err(SessionError::Decode(Refusal::LengthExceedsBatch));
        }
        self.peer_batch = usize::from(batch_size);
        self.peer_qos = qos;
        self.state = State::AwaitOpenSyn;
        Ok(Outcome::sending(sent))
    }

    fn on_init_ack<'a>(
        &mut self,
        cookie: &[u8],
        batch_size: u16,
        qos: bool,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.role != Role::Connector || self.state != State::AwaitInitAck {
            return Err(SessionError::UnexpectedMessage);
        }
        let slot = self
            .cookie
            .get_mut(..cookie.len())
            .ok_or(SessionError::Decode(Refusal::OverBound))?;
        let sent = encode::open_syn(out, self.lease_ms, self.tx_sn, cookie)?;
        if sent + STREAM_LENGTH_BYTES > usize::from(batch_size) {
            return Err(SessionError::Decode(Refusal::LengthExceedsBatch));
        }
        slot.copy_from_slice(cookie);
        self.cookie_len = cookie.len();
        self.peer_batch = usize::from(batch_size);
        self.peer_qos = qos;
        self.state = State::AwaitOpenAck;
        Ok(Outcome::sending(sent))
    }

    fn on_open_syn<'a>(
        &mut self,
        lease_ms: u64,
        initial_sn: u32,
        cookie: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.role != Role::Listener || self.state != State::AwaitOpenSyn {
            return Err(SessionError::UnexpectedMessage);
        }
        if !same(cookie, self.own_cookie()?) {
            return Err(SessionError::CookieMismatch);
        }
        let sent = encode::open_ack(out, self.lease_ms, self.tx_sn)?;
        // The reply cannot be fragmented either: it must fit the batch the peer announced in its INIT.
        if sent + STREAM_LENGTH_BYTES > self.peer_batch {
            return Err(SessionError::Decode(Refusal::LengthExceedsBatch));
        }
        self.peer_lease_ms = lease_ms;
        self.lane_sn = [initial_sn; LANES];
        self.state = State::Open;
        Ok(Outcome::sending(sent).with(Event::HandshakeComplete))
    }

    fn on_open_ack<'a>(
        &mut self,
        lease_ms: u64,
        initial_sn: u32,
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.role != Role::Connector || self.state != State::AwaitOpenAck {
            return Err(SessionError::UnexpectedMessage);
        }
        self.peer_lease_ms = lease_ms;
        self.lane_sn = [initial_sn; LANES];
        self.state = State::Open;
        Ok(Outcome::nothing().with(Event::HandshakeComplete))
    }

    /// Traffic that renews the lease, and nothing else. Before OPEN it would refresh a handshake
    /// that has not finished, so it is refused there and the session is left as it was.
    fn on_keep_alive<'a>(&mut self) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        Ok(Outcome::nothing())
    }

    fn on_close<'a>(&mut self, reason: u8) -> Result<Outcome<'a, E>, SessionError> {
        if self.state == State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        self.shut();
        Ok(Outcome::nothing().with(Event::Closed { reason }))
    }

    /// Takes a slot for a subscriber the peer declared. A peer that holds as many as the configuration
    /// declares, or declares an id it already holds, is at the limit.
    fn take_remote(&mut self, id: u64, key: &[u8]) -> Result<usize, SessionError> {
        if self.remote_n >= self.params.per_side || self.subs.find(id).is_some() {
            return Err(SessionError::SubscriberLimit);
        }
        let at = self
            .subs
            .insert(id, key)
            .map_err(|error| table_error(error, SessionError::SubscriberLimit))?;
        self.remote_n += 1;
        Ok(at)
    }

    /// A frame is applied whole or not at all: every table change it makes is journaled and undone if a
    /// later message in it is refused, and the sequence number commits only after all were accepted.
    fn on_frame<'a>(&mut self, frame: Frame<'a>) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        if let Some(slot) = self.slot_of(Lane::DEFAULT) {
            self.run_table[slot].release();
            return Err(SessionError::UnexpectedMessage);
        }
        if frame.sn != self.lane_sn[DEFAULT_LANE] {
            return Err(SessionError::SequenceMismatch);
        }
        let mut journal = [None; JOURNAL];
        let mut used = 0;
        let mut events = Events::empty();
        match self.apply_frame(&frame, &mut journal, &mut used, &mut events) {
            Ok(()) => {
                for change in journal.iter().take(used).flatten() {
                    if let Change::Unsubscribed(at) = *change {
                        self.subs.settle(at);
                    }
                }
                self.lane_sn[DEFAULT_LANE] = self.lane_sn[DEFAULT_LANE].wrapping_add(1);
                Ok(Outcome { sent: 0, events })
            }
            Err(error) => {
                for change in journal.iter().take(used).rev().flatten() {
                    match *change {
                        Change::Alias(at) => self.aliases.remove(at),
                        Change::Subscribed(at) => {
                            self.subs.remove(at);
                            self.remote_n -= 1;
                        }
                        Change::Unsubscribed(at) => {
                            self.subs.restore(at);
                            self.remote_n += 1;
                        }
                        Change::Queries(before) => self.queries = before,
                    }
                }
                Err(error)
            }
        }
    }

    /// One FRAME on a negotiated link, taken by the lane its header names. A reliable lane takes exactly its
    /// next number and refuses anything else, as a link with one lane does. A best-effort lane takes a number
    /// ahead of the last one, counts the gap and delivers; it drops a number that is not ahead and reports
    /// it. The network messages are validated and applied as a plain FRAME's are.
    fn on_lane_frame<'a>(
        &mut self,
        batch: &'a [u8],
        now_ms: u64,
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        let header = decode_lane_frame(batch)?;
        let lane = header.lane;
        let next = self.lane_sn[lane.index()];
        if lane.reliable {
            // Each lane has its own run, so a reliable FRAME on another lane may arrive inside it. A reliable
            // FRAME on the lane of an open run ends that run, as a plain FRAME does.
            if let Some(slot) = self.slot_of(lane) {
                self.run_table[slot].release();
                return Err(SessionError::UnexpectedMessage);
            }
            if header.sn != next {
                return Err(SessionError::SequenceMismatch);
            }
        } else if header.sn.wrapping_sub(next) >= HALF - 1 {
            // Upstream measures from the last number taken, one below the count held here, so a number
            // is ahead by 1 to 2^31 - 1 of it, which is 0 to 2^31 - 2 of the count.
            return Ok(Outcome::nothing().with(Event::Dropped {
                priority: lane.priority,
                cause: DropCause::StaleSequence,
            }));
        }
        let mut journal = [None; JOURNAL];
        let mut used = 0;
        let mut events = Events::empty();
        // A whole FRAME on the best-effort lane of an open run ends the run. The run is dropped, and the FRAME is
        // taken. The drop is reported after the FRAME is applied, and only if a slot is left.
        let mut frame_ended_run = false;
        if !lane.reliable
            && let Some(slot) = self.slot_of(lane)
        {
            self.run_table[slot].release();
            frame_ended_run = true;
        }
        let applied = match frame_of(header.sn, header.body, &self.params.bounds, false) {
            Ok(frame) => self.apply_frame(&frame, &mut journal, &mut used, &mut events),
            Err(refusal) => Err(refusal.into()),
        };
        match applied {
            Ok(()) => {
                for change in journal.iter().take(used).flatten() {
                    if let Change::Unsubscribed(at) = *change {
                        self.subs.settle(at);
                    }
                }
                self.lane_sn[lane.index()] = header.sn.wrapping_add(1);
                self.last_rx_ms = now_ms;
                self.now_ms = now_ms;
                if frame_ended_run {
                    events.note_first(Event::Dropped {
                        priority: lane.priority,
                        cause: DropCause::FrameDuringRun,
                    });
                }
                Ok(Outcome { sent: 0, events })
            }
            Err(error) if lane.reliable => {
                self.undo(&journal, used);
                Err(error)
            }
            Err(error) => {
                self.undo(&journal, used);
                // The number was ahead, so the lane moves past it: the sender will not send it again.
                self.lane_sn[lane.index()] = header.sn.wrapping_add(1);
                let mut events = Events::empty();
                events.note(Event::Dropped {
                    priority: lane.priority,
                    cause: DropCause::Completed(error.class()),
                });
                if frame_ended_run {
                    events.note_first(Event::Dropped {
                        priority: lane.priority,
                        cause: DropCause::FrameDuringRun,
                    });
                }
                Ok(Outcome { sent: 0, events })
            }
        }
    }

    /// Undoes the table changes of a FRAME that failed midway, newest first.
    fn undo(&mut self, journal: &[Option<Change>; JOURNAL], used: usize) {
        for change in journal.iter().take(used).rev().flatten() {
            match *change {
                Change::Alias(at) => self.aliases.remove(at),
                Change::Subscribed(at) => {
                    self.subs.remove(at);
                    self.remote_n -= 1;
                }
                Change::Unsubscribed(at) => {
                    self.subs.restore(at);
                    self.remote_n += 1;
                }
                Change::Queries(before) => self.queries = before,
            }
        }
    }

    fn apply_frame<'a>(
        &mut self,
        frame: &Frame<'a>,
        journal: &mut [Option<Change>; JOURNAL],
        used: &mut usize,
        events: &mut Events<'a, E>,
    ) -> Result<(), SessionError> {
        // Room in the journal is claimed before a table is changed, so a frame that could not be undone
        // is refused before it does anything.
        fn room(used: &usize) -> Result<(), SessionError> {
            if *used < JOURNAL {
                Ok(())
            } else {
                Err(SessionError::TooManyMessages)
            }
        }
        fn note(journal: &mut [Option<Change>; JOURNAL], used: &mut usize, change: Change) {
            if let Some(slot) = journal.get_mut(*used) {
                *slot = Some(change);
                *used += 1;
            }
        }
        for network in frame.messages() {
            match network {
                Network::DeclareSubscriber { id, key, .. } => {
                    room(used)?;
                    let at = self.take_remote(u64::from(id), key.as_bytes())?;
                    note(journal, used, Change::Subscribed(at));
                    events.push(Event::SubscriberDeclared { id })?;
                }
                Network::DeclareSubscriberAlias {
                    id,
                    mapping,
                    alias: named,
                } => {
                    room(used)?;
                    let held = resolve(&self.aliases, named, mapping)?;
                    let mut copy = [0u8; B];
                    let key = copy
                        .get_mut(..held.len())
                        .ok_or(SessionError::Decode(Refusal::OverBound))?;
                    key.copy_from_slice(held);
                    let at = self.take_remote(u64::from(id), key)?;
                    note(journal, used, Change::Subscribed(at));
                    events.push(Event::SubscriberDeclared { id })?;
                }
                Network::UndeclareSubscriber { id, key, .. } => {
                    room(used)?;
                    let at = self
                        .subs
                        .find(u64::from(id))
                        .filter(|&at| {
                            self.subs
                                .get(at)
                                .is_some_and(|(_, held)| held == key.as_bytes())
                        })
                        .ok_or(SessionError::UnknownSubscriber)?;
                    self.subs.defer_remove(at);
                    self.remote_n -= 1;
                    note(journal, used, Change::Unsubscribed(at));
                    events.push(Event::SubscriberUndeclared { id })?;
                }
                Network::UndeclareSubscriberById { id } => {
                    room(used)?;
                    let at = self
                        .subs
                        .find(u64::from(id))
                        .ok_or(SessionError::UnknownSubscriber)?;
                    self.subs.defer_remove(at);
                    self.remote_n -= 1;
                    note(journal, used, Change::Unsubscribed(at));
                    events.push(Event::SubscriberUndeclared { id })?;
                }
                Network::PushPut {
                    key,
                    attachment,
                    payload,
                    ..
                } => deliver(&self.subs, key.as_bytes(), attachment, payload, events)?,
                Network::PushPutAlias {
                    mapping,
                    alias: named,
                    attachment,
                    payload,
                    ..
                } => {
                    let held = resolve(&self.aliases, named, mapping)?;
                    deliver(&self.subs, held, attachment, payload, events)?;
                }
                Network::DeclareKeyExpr { id, key } => {
                    // The same id again is a redeclaration whether or not it names the same key; a
                    // new id with every slot taken is over the bound.
                    if self.aliases.find(u64::from(id)).is_some() {
                        return Err(SessionError::Decode(Refusal::InvalidKeyexpr));
                    }
                    room(used)?;
                    let at =
                        self.aliases
                            .insert(u64::from(id), key.as_bytes())
                            .map_err(|error| {
                                table_error(error, SessionError::Decode(Refusal::OverBound))
                            })?;
                    note(journal, used, Change::Alias(at));
                }
                Network::Oam | Network::DeclareFinal => {}
                Network::DeclareQueryable { id, mapping, key } => {
                    room(used)?;
                    self.query_key(key, mapping)?;
                    if self.queries.peer_queryable.is_some() {
                        return Err(SessionError::QueryableLimit);
                    }
                    note(journal, used, Change::Queries(self.queries));
                    self.queries.peer_queryable = Some(id);
                    events.push(Event::QueryableDeclared { id })?;
                }
                Network::UndeclareQueryable { id } => {
                    room(used)?;
                    if self.queries.peer_queryable != Some(id) {
                        return Err(SessionError::UnknownQueryable);
                    }
                    note(journal, used, Change::Queries(self.queries));
                    self.queries.peer_queryable = None;
                    events.push(Event::QueryableUndeclared { id })?;
                }
                Network::Request {
                    id,
                    mapping,
                    key,
                    timeout_ms,
                } => {
                    room(used)?;
                    if self.queries.own_queryable.is_none() {
                        return Err(SessionError::UndeclaredKey);
                    }
                    let named = self.query_key(key, mapping)?;
                    if !self.answers(named) {
                        return Err(SessionError::UndeclaredKey);
                    }
                    if self.queries.peer_request.is_some() {
                        return Err(SessionError::RequestLimit);
                    }
                    note(journal, used, Change::Queries(self.queries));
                    self.queries.peer_request = Some(id);
                    events.push(Event::QueryReceived {
                        request: id,
                        timeout_ms,
                    })?;
                }
                Network::Response {
                    id,
                    mapping,
                    key,
                    payload,
                } => {
                    room(used)?;
                    if self.queries.own_request != Some(id) {
                        return Err(SessionError::UnexpectedMessage);
                    }
                    self.query_key(key, mapping)?;
                    events.push(Event::ReplyDelivered {
                        request: id,
                        payload,
                    })?;
                }
                Network::ResponseFinal { id } => {
                    room(used)?;
                    if self.queries.own_request != Some(id) {
                        return Err(SessionError::UnexpectedMessage);
                    }
                    note(journal, used, Change::Queries(self.queries));
                    self.queries.own_request = None;
                    events.push(Event::QueryFinished { request: id })?;
                }
            }
        }
        Ok(())
    }

    /// One FRAGMENT of a session that holds no lanes: joined into `cell`, on the default lane. A refusal at any
    /// point frees the cell and leaves the session's sequence number where it was.
    fn on_fragment<'a>(
        &mut self,
        batch: &[u8],
        now_ms: u64,
        cell: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        let fragment = match decode_fragment(batch, Some(usize::from(self.params.announced))) {
            Ok(fragment) => fragment,
            Err(error) => {
                if let Some(slot) = self.slot_of(Lane::DEFAULT) {
                    self.run_table[slot].release();
                }
                return Err(error.into());
            }
        };
        self.take_fragment(Lane::DEFAULT, &fragment, now_ms, cell)
    }

    /// One FRAGMENT of a session that negotiated lanes, joined into `cell`, the storage of
    /// [`Self::run_slot`] for the lane the header names. A reliable lane takes the next number of its own
    /// counter and refuses anything else. A best-effort lane counts the gap and drops what it cannot take, as an
    /// [`Event::Dropped`]. A lane with no free slot has no cell: the caller passes any cell, which that fragment
    /// does not use.
    pub fn on_lane_fragment<'a>(
        &mut self,
        batch: &[u8],
        now_ms: u64,
        cell: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        if self.state != State::Open || !self.params.fragments || !self.lanes() {
            return Err(SessionError::UnexpectedMessage);
        }
        let header = match decode_lane_fragment(batch, Some(usize::from(self.params.announced))) {
            Ok(header) => header,
            Err(error) => {
                // A refused fragment ends the run of its lane, as it does on the one-cell path. A header that
                // names no lane ends none.
                // A best-effort lane keeps its run: only a fragment it took can break it.
                if let Some(slot) = peek_fragment_lane(batch)
                    .filter(|lane| lane.reliable)
                    .and_then(|lane| self.slot_of(lane))
                {
                    self.run_table[slot].release();
                }
                return Err(error.into());
            }
        };
        let fragment = Fragment {
            more: header.more,
            sn: header.sn,
            data: header.data,
        };
        let outcome = if header.lane.reliable {
            self.take_fragment(header.lane, &fragment, now_ms, cell)?
        } else {
            self.take_best_effort_fragment(header.lane, &fragment, now_ms, cell)?
        };
        self.last_rx_ms = now_ms;
        self.now_ms = now_ms;
        Ok(outcome)
    }

    /// Reads the message of a completed run as a Put held to what a whole-frame Put is held to.
    fn put_event<'a>(&self, message: &[u8]) -> Result<Event<'a>, SessionError> {
        let subs = &self.subs;
        let subscribed = |key: &[u8]| subscribed_to(subs, key);
        let rules = PutRules {
            max_key: self.params.bounds.key,
            max_payload: self.params.bounds.payload as u64,
            aliases: Some(&self.aliases),
            subscribed: &subscribed,
        };
        let view = decode_put(message, &rules)?;
        let offset = (view.payload.as_ptr() as usize).saturating_sub(message.as_ptr() as usize);
        Ok(Event::SampleStored {
            sequence: view.attachment.sequence,
            timestamp: view.attachment.timestamp,
            offset,
            len: view.payload.len(),
        })
    }

    /// One best-effort fragment. The lane counts past every number that is ahead, so the sender's next number is
    /// the one it expects, and what it cannot take it drops and reports. A run that breaks makes the lane discard
    /// fragments through the next final one, so the leftovers of the message never join into a sample.
    fn take_best_effort_fragment<'a>(
        &mut self,
        lane: Lane,
        fragment: &Fragment<'_>,
        now_ms: u64,
        cell: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let index = lane.index();
        let (timeout, limit) = (self.params.timeout_ms, self.params.message_limit);
        let dropped = |cause| Event::Dropped {
            priority: lane.priority,
            cause,
        };
        let mut events = Events::empty();
        let mut slot = self.slot_of(lane);
        if let Some(open) = slot.filter(|open| self.run_table[*open].expired(now_ms, timeout)) {
            self.run_table[open].release();
            self.discarding[index] = true;
            events.note(dropped(DropCause::ReassemblyTimeout));
            slot = None;
        }
        // The same measure as a FRAME: ahead of the last number taken by 1 to 2^31 - 1.
        if fragment.sn.wrapping_sub(self.lane_sn[index]) >= HALF - 1 {
            events.note(dropped(DropCause::StaleSequence));
            return Ok(Outcome { sent: 0, events });
        }
        self.lane_sn[index] = fragment.sn.wrapping_add(1);
        if self.discarding[index] {
            self.discarding[index] = fragment.more;
            events.note(dropped(DropCause::Discarded));
            return Ok(Outcome { sent: 0, events });
        }
        let broken = match slot {
            Some(open) if self.run_table[open].next_sn() != fragment.sn => {
                self.run_table[open].release();
                Some(DropCause::FragmentSequence)
            }
            None if self.free_slot().is_none() => Some(DropCause::LaneLimit),
            _ => None,
        };
        if let Some(cause) = broken {
            self.discarding[index] = fragment.more;
            events.note(dropped(cause));
            return Ok(Outcome { sent: 0, events });
        }
        let open = slot
            .or_else(|| self.free_slot())
            .ok_or(SessionError::LaneLimit)?;
        let progress =
            self.run_table[open].accept(fragment, cell, fragment.sn, now_ms, timeout, limit);
        let result = match progress {
            Ok(Progress::Open) => {
                self.run_lane[open] = lane;
                return Ok(Outcome { sent: 0, events });
            }
            Ok(Progress::Complete(_)) => self.run_table[open]
                .finish(cell)
                .map_err(SessionError::from)
                .and_then(|(message, _)| self.put_event(message)),
            Err(error) => Err(error.into()),
        };
        match result {
            Ok(event) => events.push(event)?,
            Err(error) => {
                self.discarding[index] = fragment.more;
                events.note(dropped(DropCause::Completed(error.class())));
            }
        }
        Ok(Outcome { sent: 0, events })
    }

    /// Joins one fragment into the run of `lane` and, when the last arrives, reads the message as a Put held to
    /// what a whole-frame Put is held to. A refusal frees the run and leaves the lane's counter where it was.
    fn take_fragment<'a>(
        &mut self,
        lane: Lane,
        fragment: &Fragment<'_>,
        now_ms: u64,
        cell: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let expected = self.lane_sn[lane.index()];
        let slot = match self.slot_of(lane) {
            Some(slot) => slot,
            None => {
                // A first fragment is judged by its number before the room for it, as upstream judges it.
                if fragment.sn != expected {
                    return Err(SessionError::SequenceMismatch);
                }
                self.free_slot().ok_or(SessionError::LaneLimit)?
            }
        };
        let (timeout, limit) = (self.params.timeout_ms, self.params.message_limit);
        let progress =
            self.run_table[slot].accept(fragment, cell, expected, now_ms, timeout, limit)?;
        self.run_lane[slot] = lane;
        if progress == Progress::Open {
            return Ok(Outcome::nothing());
        }
        let (message, next) = self.run_table[slot].finish(cell)?;
        let event = self.put_event(message)?;
        self.lane_sn[lane.index()] = next;
        Ok(Outcome::nothing().with(event))
    }

    /// Closes the session with a CLOSE batch once `now_ms` is past the lease deadline. An open
    /// session that has sent nothing for a quarter of its own announced lease writes a KEEP_ALIVE; before
    /// OPEN, or while the lent storage cannot take one, it only accepts and does nothing.
    pub fn tick<'a>(
        &mut self,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let expired = self.expire(now_ms, out)?;
        if expired.sent != 0 {
            self.now_ms = self.now_ms.max(now_ms);
            return Ok(expired);
        }
        if self.state == State::Open && now_ms >= self.keep_alive_due() {
            let sent = encode::keep_alive(out)?;
            self.now_ms = self.now_ms.max(now_ms);
            self.sent_now(now_ms);
            return Ok(Outcome {
                sent,
                events: expired.events,
            });
        }
        self.now_ms = self.now_ms.max(now_ms);
        Ok(expired)
    }

    /// The expiry half of [`tick`](Self::tick): closes the session once `now_ms` is past the
    /// lease deadline and never writes a KEEP_ALIVE. A link whose single send slot is occupied
    /// calls this, so a keep-alive cannot collide with the batch waiting there.
    pub fn tick_lease<'a>(
        &mut self,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let outcome = self.expire(now_ms, out)?;
        self.now_ms = self.now_ms.max(now_ms);
        Ok(outcome)
    }

    /// The expiry check without the clock: a refused call must leave the session as it was, so
    /// the callers advance `now_ms` only after the whole operation has succeeded.
    fn expire<'a>(&mut self, now_ms: u64, out: &mut [u8]) -> Result<Outcome<'a, E>, SessionError> {
        // A run whose last fragment never came is refused once its deadline has passed and its storage is
        // released; the session itself stays open.
        // A reliable lane refuses. A best-effort lane drops the run, discards through the next final fragment and
        // reports it, so the session stays as it was for the caller that counts drops.
        let timeout = self.params.timeout_ms;
        let mut late = false;
        let mut events = Events::empty();
        for slot in 0..R {
            if !self.run_table[slot].expired(now_ms, timeout) {
                continue;
            }
            self.run_table[slot].release();
            let lane = self.run_lane[slot];
            if lane.reliable {
                late = true;
            } else {
                self.discarding[lane.index()] = true;
                events.note(Event::Dropped {
                    priority: lane.priority,
                    cause: DropCause::ReassemblyTimeout,
                });
            }
        }
        if late {
            return Err(FragmentError::ReassemblyTimeout.into());
        }
        match self.lease_deadline() {
            Some(deadline) if now_ms > deadline => {
                let sent = encode::close(out, CLOSE_EXPIRED, true)?;
                self.shut();
                Ok(Outcome::sending(sent).with(Event::Closed {
                    reason: CLOSE_EXPIRED,
                }))
            }
            _ => Ok(Outcome { sent: 0, events }),
        }
    }

    /// When the next KEEP_ALIVE is due: a quarter of the lease this side announced after it last
    /// sent. The peer closes after one of that lease without hearing from us, so our own lease
    /// sets the cadence, not the one the peer announced. A lease under four milliseconds still
    /// spaces keep-alives a millisecond apart, so a pump never queues a second one in the instant
    /// of the first.
    pub fn keep_alive_due(&self) -> u64 {
        self.last_tx_ms.saturating_add((self.lease_ms / 4).max(1))
    }

    /// Closes the session locally with a CLOSE batch carrying `reason`.
    pub fn close<'a>(
        &mut self,
        reason: u8,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        let sent = encode::close(out, reason, true)?;
        self.shut();
        Ok(Outcome::sending(sent).with(Event::Closed { reason }))
    }

    /// The bounds this side writes under: its own, with the batch the smaller of its own and the peer's.
    fn send_bounds(&self) -> Bounds {
        Bounds {
            batch: self.send_body_max(),
            ..self.params.bounds
        }
    }

    /// Builds one reliable FRAME with the next sequence number; the number is
    /// spent only when the frame was built.
    fn send_frame<'a>(
        &mut self,
        out: &mut [u8],
        build: impl FnOnce(&mut FrameEncoder<'_>) -> Result<(), EncodeError>,
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        let bounds = self.send_bounds();
        let mut frame = FrameEncoder::with_bounds(out, self.tx_sn, bounds)?;
        build(&mut frame)?;
        let sent = frame.finish()?;
        self.tx_sn = self.tx_sn.wrapping_add(1);
        self.sent_now(self.now_ms);
        Ok(Outcome::sending(sent))
    }

    /// The key a query message names. A key in full is its own. An alias in the sender's mapping is one the peer
    /// declared. An alias in the receiver's mapping is one this side declared, and is held under [`LOCAL`].
    fn query_key<'k>(
        &'k self,
        key: QueryKey<'k>,
        mapping: Mapping,
    ) -> Result<&'k [u8], SessionError> {
        match key {
            QueryKey::Full(key) => Ok(key.as_bytes()),
            QueryKey::Alias(alias) => match mapping {
                Mapping::Sender => resolve(&self.aliases, alias, mapping),
                Mapping::Receiver => self
                    .aliases
                    .key_of(LOCAL | u64::from(alias))
                    .ok_or(SessionError::Decode(Refusal::InvalidKeyexpr)),
            },
        }
    }

    /// Whether `key` is the one this side's queryable answers.
    fn answers(&self, key: &[u8]) -> bool {
        self.queries.own_queryable.is_some()
            && self
                .aliases
                .key_of(LOCAL | u64::from(self.queries.own_alias))
                .is_some_and(|held| held == key)
    }

    /// Writes a FRAME declaring an alias for `key` and this side's queryable on it, as a stock peer does. One
    /// queryable is held at a time, and its alias takes a slot of the alias table.
    pub fn send_declare_queryable<'a>(
        &mut self,
        id: u32,
        alias: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.queries.own_queryable.is_some() {
            return Err(SessionError::QueryableLimit);
        }
        if alias == 0 || alias > u32::from(u16::MAX) {
            return Err(SessionError::Decode(Refusal::InvalidKeyexpr));
        }
        let at = self
            .aliases
            .insert(LOCAL | u64::from(alias), key.as_bytes())
            .map_err(|error| table_error(error, SessionError::Decode(Refusal::OverBound)))?;
        let sent = self.send_frame(out, |frame| {
            frame.declare_keyexpr(alias, key)?;
            frame.declare_queryable_alias(id, alias)
        });
        match sent {
            Ok(outcome) => {
                self.queries.own_queryable = Some(id);
                self.queries.own_alias = alias;
                Ok(outcome)
            }
            Err(error) => {
                self.aliases.remove(at);
                Err(error)
            }
        }
    }

    /// Writes a FRAME withdrawing this side's queryable. The alias stays held.
    pub fn send_undeclare_queryable<'a>(
        &mut self,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let id = self
            .queries
            .own_queryable
            .ok_or(SessionError::UnknownQueryable)?;
        let outcome = self.send_frame(out, |frame| frame.undeclare_queryable(id))?;
        self.queries.own_queryable = None;
        Ok(outcome)
    }

    /// The queryable the peer declared, by id.
    pub const fn peer_queryable(&self) -> Option<u32> {
        self.queries.peer_queryable
    }

    /// The request the peer asked that this side has not yet finished.
    pub const fn peer_request(&self) -> Option<u32> {
        self.queries.peer_request
    }

    /// The request this side asked that the peer has not yet finished.
    pub const fn own_request(&self) -> Option<u32> {
        self.queries.own_request
    }

    /// Writes a FRAME with a REQUEST for the latest value on `target`. One request is outstanding at a time.
    pub fn send_request<'a>(
        &mut self,
        id: u32,
        target: encode::QueryTarget<'_>,
        timeout_ms: u32,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.queries.own_request.is_some() {
            return Err(SessionError::RequestLimit);
        }
        if let encode::QueryTarget::ReceiverAlias(alias) = target
            && self.aliases.find(u64::from(alias)).is_none()
        {
            return Err(SessionError::Decode(Refusal::InvalidKeyexpr));
        }
        let outcome = self.send_frame(out, |frame| frame.request(id, target, timeout_ms))?;
        self.queries.own_request = Some(id);
        Ok(outcome)
    }

    /// Writes a FRAME with one RESPONSE to the request the peer asked: `payload` under `key`, from the
    /// responder `zid`. The request stays open until [`Self::send_response_final`].
    pub fn send_response<'a>(
        &mut self,
        key: &str,
        zid: &[u8],
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let id = self
            .queries
            .peer_request
            .ok_or(SessionError::UnexpectedMessage)?;
        self.send_frame(out, |frame| frame.response(id, key, zid, payload))
    }

    /// Writes a FRAME that ends the replies to the request the peer asked.
    pub fn send_response_final<'a>(
        &mut self,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let id = self
            .queries
            .peer_request
            .ok_or(SessionError::UnexpectedMessage)?;
        let outcome = self.send_frame(out, |frame| frame.response_final(id))?;
        self.queries.peer_request = None;
        Ok(outcome)
    }

    /// Writes a FRAME declaring this side's subscriber on `key`. A full key expression travels with
    /// the sender mapping, as the upstream encoder writes it.
    pub fn send_declare_subscriber<'a>(
        &mut self,
        id: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if self.local_n >= self.params.local || self.subs.find(LOCAL | u64::from(id)).is_some() {
            return Err(SessionError::SubscriberLimit);
        }
        let outcome = self.send_frame(out, |frame| {
            frame.declare_subscriber(id, Mapping::Sender, key)
        })?;
        self.subs
            .insert(LOCAL | u64::from(id), key.as_bytes())
            .map_err(|error| table_error(error, SessionError::SubscriberLimit))?;
        self.local_n += 1;
        Ok(outcome)
    }

    /// The ids of the liveliness tokens this side holds, in the order it declared them.
    pub fn tokens_held(&self) -> &[u32] {
        &self.tokens[..self.token_n]
    }

    /// Writes a FRAME declaring the liveliness token `id` under `key`, with the key in full and the sender mapping. Only a
    /// session with the client role writes a token: a router lists a node from the tokens its client declares.
    pub fn send_declare_token<'a>(
        &mut self,
        id: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if !self.client {
            return Err(SessionError::InvalidConfig);
        }
        if self.state == State::Open
            && (self.token_n >= MAX_TOKENS || self.tokens_held().contains(&id))
        {
            return Err(SessionError::TokenLimit);
        }
        let outcome =
            self.send_frame(out, |frame| frame.declare_token(id, Mapping::Sender, key))?;
        self.tokens[self.token_n] = id;
        self.token_n += 1;
        Ok(outcome)
    }

    /// Writes a FRAME withdrawing the liveliness token `id`. The session keeps every other token declared.
    pub fn send_undeclare_token<'a>(
        &mut self,
        id: u32,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        if !self.client {
            return Err(SessionError::InvalidConfig);
        }
        let at = self
            .tokens_held()
            .iter()
            .position(|&held| held == id)
            .ok_or(SessionError::UnknownToken)?;
        let outcome = self.send_frame(out, |frame| frame.undeclare_token(id))?;
        self.tokens.copy_within(at + 1..self.token_n, at);
        self.token_n -= 1;
        Ok(outcome)
    }

    /// Writes a FRAME undeclaring this side's subscriber `id` on `key`.
    pub fn send_undeclare_subscriber<'a>(
        &mut self,
        id: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        let at = self
            .subs
            .find(LOCAL | u64::from(id))
            .filter(|&at| {
                self.subs
                    .get(at)
                    .is_some_and(|(_, held)| held == key.as_bytes())
            })
            .ok_or(SessionError::UnknownSubscriber)?;
        let outcome = self.send_frame(out, |frame| {
            frame.undeclare_subscriber(id, Mapping::Sender, key)
        })?;
        self.subs.remove(at);
        self.local_n -= 1;
        Ok(outcome)
    }

    /// Whether a Put may be written on `key`. A session with no client role needs the peer to have declared a
    /// subscriber on it. A router declares none to a client, so a session with the client role writes a whole Put
    /// on any key that validates. A Put in fragments keeps the check for every session, because no exam observes a
    /// client writing fragments.
    fn check_put(
        &self,
        key: &str,
        attachment: &[u8],
        payload_len: usize,
        whole: bool,
    ) -> Result<(), SessionError> {
        if !(self.client && whole)
            && self
                .subs
                .find_by(|id, held| id & LOCAL == 0 && held == key.as_bytes())
                .is_none()
        {
            return Err(SessionError::UndeclaredKey);
        }
        encode::validate_put(key, attachment, payload_len, &self.params.bounds)?;
        Ok(())
    }

    /// Whether a Put of `payload_len` bytes under `key` travels in one FRAME at the next sequence number.
    pub fn put_fits_one_frame(&self, key: &str, attachment: &[u8], payload_len: usize) -> bool {
        let message = PutMessage::new(key.as_bytes(), attachment, &[]);
        let size =
            Source::len(&message) - 1 + super::limits::leb_bytes(payload_len as u64) + payload_len;
        fits_one_frame(size, self.send_body_max() + STREAM_LENGTH_BYTES, self.tx_sn)
    }

    /// Writes a FRAME carrying a Put to a key the peer declared; `attachment` is from [`encode::attachment`].
    /// A Put that does not fit one frame is refused as over the bound in a session that cannot
    /// fragment, and as [`SessionError::NeedsFragments`] in one that can.
    pub fn send_put<'a>(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        self.send_put_qos(key, attachment, payload, Qos::default(), out)
    }

    /// [`send_put`](Self::send_put) with the QoS the PUSH states. The default QoS writes no extension.
    pub fn send_put_qos<'a>(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        qos: Qos,
        out: &mut [u8],
    ) -> Result<Outcome<'a, E>, SessionError> {
        self.check_whole_put(key, attachment, payload.len())?;
        self.send_frame(out, |frame| {
            frame.push_put_qos(Mapping::Sender, key, qos, attachment, payload)
        })
    }

    /// What `send_put` checks before it builds a frame, and nothing more: that the session is open, the Put's key,
    /// attachment and size, and that it travels in one FRAME. It changes nothing, so a caller that is about to
    /// discard the Put refuses the same Puts `send_put` refuses.
    pub fn check_whole_put(
        &self,
        key: &str,
        attachment: &[u8],
        payload_len: usize,
    ) -> Result<(), SessionError> {
        self.check_put(key, attachment, payload_len, true)?;
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        if !self.put_fits_one_frame(key, attachment, payload_len) {
            return Err(if self.params.fragments {
                SessionError::NeedsFragments
            } else {
                SessionError::Decode(Refusal::OverBound)
            });
        }
        Ok(())
    }

    /// Writes the next FRAGMENT of a Put that does not fit one frame, starting at byte `at` of the
    /// message (0 for the first) and returning the position to resume from, or `None` once the whole
    /// message has been written. The caller passes the same key, attachment and payload throughout.
    pub fn send_put_fragment<'a>(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        at: usize,
        out: &mut [u8],
    ) -> Result<(Outcome<'a, E>, Option<usize>), SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        if !self.params.fragments {
            return Err(SessionError::Decode(Refusal::OverBound));
        }
        if at == 0 {
            self.check_put(key, attachment, payload.len(), false)?;
        }
        let message = PutMessage::new(key.as_bytes(), attachment, payload);
        let mut splitter = Splitter::resume(
            message,
            self.send_body_max() + STREAM_LENGTH_BYTES,
            at,
            self.tx_sn,
        )?;
        let Some(sent) = splitter.next_body(out)? else {
            return Ok((Outcome::nothing(), None));
        };
        self.tx_sn = splitter.next_sn();
        self.sent_now(self.now_ms);
        let next = (!splitter.done()).then(|| splitter.position());
        Ok((Outcome::sending(sent), next))
    }
}
