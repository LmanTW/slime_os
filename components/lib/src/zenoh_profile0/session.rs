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
//! lease expiry. The machine tracks two subscriber slots: the subscription this
//! side declared, which a received PUSH must match to be delivered, and the one
//! the peer declared, which a Put this side sends must match.

use super::encode::{self, EncodeError, FrameEncoder};
use super::{
    Frame, MAX_BATCH_BYTES, MAX_COOKIE_BYTES, MAX_KEY_BYTES, Mapping, Message, Network, Refusal,
    decode_batch,
};
use slime_proto::zenoh_profile as p;

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

/// Events one received batch can yield; this is the contract's outstanding-sample bound.
pub const MAX_EVENTS: usize = 4;
/// The batch size this side advertises in INIT.
const OUR_BATCH_SIZE: u16 = MAX_BATCH_BYTES as u16;
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
    /// A FRAME yielding more than [`MAX_EVENTS`] events.
    TooManyMessages,
}

impl From<Refusal> for SessionError {
    fn from(refusal: Refusal) -> Self {
        Self::Decode(refusal)
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
        sequence: i64,
        timestamp: i64,
        payload: &'a [u8],
    },
    SubscriberUndeclared {
        id: u32,
    },
    Closed {
        reason: u8,
    },
}

/// Up to [`MAX_EVENTS`] events, in the order they happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Events<'a> {
    items: [Option<Event<'a>>; MAX_EVENTS],
    len: usize,
}

impl<'a> Events<'a> {
    const fn empty() -> Self {
        Self {
            items: [None; MAX_EVENTS],
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
pub struct Outcome<'a> {
    /// Length of the batch body written at the start of the lent storage; 0 means nothing to send.
    pub sent: usize,
    pub events: Events<'a>,
}

impl<'a> Outcome<'a> {
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

#[derive(Clone, Copy, Debug)]
struct Subscriber {
    id: u32,
    key: [u8; MAX_KEY_BYTES],
    len: usize,
}

impl Subscriber {
    fn new(id: u32, key: &str) -> Result<Self, SessionError> {
        let bytes = key.as_bytes();
        let mut buffer = [0u8; MAX_KEY_BYTES];
        buffer
            .get_mut(..bytes.len())
            .ok_or(SessionError::Decode(Refusal::OverBound))?
            .copy_from_slice(bytes);
        Ok(Self {
            id,
            key: buffer,
            len: bytes.len(),
        })
    }

    fn key(&self) -> &[u8] {
        self.key.get(..self.len).unwrap_or(&[])
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    role: Role,
    state: State,
    zid: [u8; ZID_BYTES],
    zid_len: usize,
    lease_ms: u64,
    peer_lease_ms: u64,
    tx_sn: u32,
    rx_sn: u32,
    cookie: [u8; MAX_COOKIE_BYTES],
    cookie_len: usize,
    last_rx_ms: u64,
    /// The subscription this side declared; received PUSH messages are delivered only to its key.
    local: Option<Subscriber>,
    /// The subscription the peer declared; a Put this side sends must name its key.
    remote: Option<Subscriber>,
}

fn same(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

impl Session {
    /// A session in [`State::Idle`], or [`SessionError::InvalidConfig`] when
    /// the encoder could not announce `config`.
    pub fn new(role: Role, config: &Config<'_>) -> Result<Self, SessionError> {
        let mut scratch = [0u8; 2 * MAX_BATCH_BYTES];
        encode::init_syn(&mut scratch, config.zid, OUR_BATCH_SIZE)
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
            encode::init_ack(&mut scratch, config.zid, OUR_BATCH_SIZE, config.cookie)
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
            zid,
            zid_len: config.zid.len(),
            lease_ms: config.lease_ms,
            peer_lease_ms: 0,
            tx_sn: config.initial_sn,
            rx_sn: 0,
            cookie,
            cookie_len,
            last_rx_ms: 0,
            local: None,
            remote: None,
        })
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

    /// The sequence number the next reliable FRAME this side sends carries.
    pub const fn next_tx_sn(&self) -> u32 {
        self.tx_sn
    }

    /// The sequence number the next received reliable FRAME must carry; meaningful once open.
    pub const fn expected_rx_sn(&self) -> u32 {
        self.rx_sn
    }

    /// The lease the peer announced, 0 until the handshake completes.
    pub const fn peer_lease_ms(&self) -> u64 {
        self.peer_lease_ms
    }

    /// The id of the subscriber this side declared, if any.
    pub fn subscriber_id(&self) -> Option<u32> {
        self.local.as_ref().map(|slot| slot.id)
    }

    /// The key of the subscriber this side declared, if any.
    pub fn subscriber_key(&self) -> Option<&str> {
        let slot = self.local.as_ref()?;
        core::str::from_utf8(slot.key()).ok()
    }

    /// The id of the subscriber the peer declared, if any.
    pub fn peer_subscriber_id(&self) -> Option<u32> {
        self.remote.as_ref().map(|slot| slot.id)
    }

    /// The key of the subscriber the peer declared, if any.
    pub fn peer_subscriber_key(&self) -> Option<&str> {
        let slot = self.remote.as_ref()?;
        core::str::from_utf8(slot.key()).ok()
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
        self.local = None;
        self.remote = None;
    }

    /// Connector only: writes INIT_SYN and starts waiting for INIT_ACK.
    pub fn connect<'a>(
        &mut self,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        if self.role != Role::Connector || self.state != State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        let sent = encode::init_syn(out, self.own_zid()?, OUR_BATCH_SIZE)?;
        self.state = State::AwaitInitAck;
        self.last_rx_ms = now_ms;
        Ok(Outcome::sending(sent))
    }

    /// Decodes `batch` (a body without its stream prefix) and applies it.
    pub fn on_batch<'a>(
        &mut self,
        batch: &'a [u8],
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        let message = decode_batch(batch)?;
        self.on_message(message, now_ms, out)
    }

    /// Applies one decoded message. An accepted message refreshes the lease.
    pub fn on_message<'a>(
        &mut self,
        message: Message<'a>,
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        let outcome = match message {
            Message::InitSyn { .. } => self.on_init_syn(out)?,
            Message::InitAck { cookie, .. } => self.on_init_ack(cookie, out)?,
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
            Message::Frame(frame) => self.on_frame(frame)?,
        };
        self.last_rx_ms = now_ms;
        Ok(outcome)
    }

    fn on_init_syn<'a>(&mut self, out: &mut [u8]) -> Result<Outcome<'a>, SessionError> {
        if self.role != Role::Listener || self.state != State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        let sent = encode::init_ack(out, self.own_zid()?, OUR_BATCH_SIZE, self.own_cookie()?)?;
        self.state = State::AwaitOpenSyn;
        Ok(Outcome::sending(sent))
    }

    fn on_init_ack<'a>(
        &mut self,
        cookie: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        if self.role != Role::Connector || self.state != State::AwaitInitAck {
            return Err(SessionError::UnexpectedMessage);
        }
        let slot = self
            .cookie
            .get_mut(..cookie.len())
            .ok_or(SessionError::Decode(Refusal::OverBound))?;
        let sent = encode::open_syn(out, self.lease_ms, self.tx_sn, cookie)?;
        slot.copy_from_slice(cookie);
        self.cookie_len = cookie.len();
        self.state = State::AwaitOpenAck;
        Ok(Outcome::sending(sent))
    }

    fn on_open_syn<'a>(
        &mut self,
        lease_ms: u64,
        initial_sn: u32,
        cookie: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        if self.role != Role::Listener || self.state != State::AwaitOpenSyn {
            return Err(SessionError::UnexpectedMessage);
        }
        if !same(cookie, self.own_cookie()?) {
            return Err(SessionError::CookieMismatch);
        }
        let sent = encode::open_ack(out, self.lease_ms, self.tx_sn)?;
        self.peer_lease_ms = lease_ms;
        self.rx_sn = initial_sn;
        self.state = State::Open;
        Ok(Outcome::sending(sent).with(Event::HandshakeComplete))
    }

    fn on_open_ack<'a>(
        &mut self,
        lease_ms: u64,
        initial_sn: u32,
    ) -> Result<Outcome<'a>, SessionError> {
        if self.role != Role::Connector || self.state != State::AwaitOpenAck {
            return Err(SessionError::UnexpectedMessage);
        }
        self.peer_lease_ms = lease_ms;
        self.rx_sn = initial_sn;
        self.state = State::Open;
        Ok(Outcome::nothing().with(Event::HandshakeComplete))
    }

    fn on_close<'a>(&mut self, reason: u8) -> Result<Outcome<'a>, SessionError> {
        if self.state == State::Idle {
            return Err(SessionError::UnexpectedMessage);
        }
        self.shut();
        Ok(Outcome::nothing().with(Event::Closed { reason }))
    }

    /// A frame is applied whole or not at all: the slot and the sequence number
    /// commit only after every network message was accepted.
    fn on_frame<'a>(&mut self, frame: Frame<'a>) -> Result<Outcome<'a>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::UnexpectedMessage);
        }
        if frame.sn != self.rx_sn {
            return Err(SessionError::SequenceMismatch);
        }
        let mut remote = self.remote;
        let local = self.local;
        let mut events = Events::empty();
        for network in frame.messages() {
            match network {
                Network::DeclareSubscriber { id, key, .. } => {
                    if remote.is_some() {
                        return Err(SessionError::SubscriberLimit);
                    }
                    remote = Some(Subscriber::new(id, key)?);
                    events.push(Event::SubscriberDeclared { id })?;
                }
                Network::UndeclareSubscriber { id, key, .. } => match remote {
                    Some(held) if held.id == id && held.key() == key.as_bytes() => {
                        remote = None;
                        events.push(Event::SubscriberUndeclared { id })?;
                    }
                    _ => return Err(SessionError::UnknownSubscriber),
                },
                Network::PushPut {
                    key,
                    attachment,
                    payload,
                    ..
                } => match local {
                    Some(held) if held.key() == key.as_bytes() => {
                        events.push(Event::SampleDelivered {
                            sequence: attachment.sequence,
                            timestamp: attachment.timestamp,
                            payload,
                        })?;
                    }
                    _ => return Err(SessionError::UndeclaredKey),
                },
            }
        }
        self.remote = remote;
        self.rx_sn = self.rx_sn.wrapping_add(1);
        Ok(Outcome { sent: 0, events })
    }

    /// Closes the session with a CLOSE batch once `now_ms` is past the lease
    /// deadline; otherwise accepts and does nothing.
    pub fn tick<'a>(&mut self, now_ms: u64, out: &mut [u8]) -> Result<Outcome<'a>, SessionError> {
        match self.lease_deadline() {
            Some(deadline) if now_ms > deadline => {
                let sent = encode::close(out, CLOSE_EXPIRED, true)?;
                self.shut();
                Ok(Outcome::sending(sent).with(Event::Closed {
                    reason: CLOSE_EXPIRED,
                }))
            }
            _ => Ok(Outcome::nothing()),
        }
    }

    /// Closes the session locally with a CLOSE batch carrying `reason`.
    pub fn close<'a>(&mut self, reason: u8, out: &mut [u8]) -> Result<Outcome<'a>, SessionError> {
        if self.state == State::Closed {
            return Err(SessionError::Closed);
        }
        let sent = encode::close(out, reason, true)?;
        self.shut();
        Ok(Outcome::sending(sent).with(Event::Closed { reason }))
    }

    /// Builds one reliable FRAME with the next sequence number; the number is
    /// spent only when the frame was built.
    fn send_frame<'a>(
        &mut self,
        out: &mut [u8],
        build: impl FnOnce(&mut FrameEncoder<'_>) -> Result<(), EncodeError>,
    ) -> Result<Outcome<'a>, SessionError> {
        if self.state != State::Open {
            return Err(SessionError::NotOpen);
        }
        let mut frame = FrameEncoder::new(out, self.tx_sn)?;
        build(&mut frame)?;
        let sent = frame.finish()?;
        self.tx_sn = self.tx_sn.wrapping_add(1);
        Ok(Outcome::sending(sent))
    }

    /// Writes a FRAME declaring this side's subscriber on `key`. A full key expression travels with
    /// the sender mapping, as the upstream encoder writes it.
    pub fn send_declare_subscriber<'a>(
        &mut self,
        id: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        if self.local.is_some() {
            return Err(SessionError::SubscriberLimit);
        }
        let held = Subscriber::new(id, key)?;
        let outcome = self.send_frame(out, |frame| {
            frame.declare_subscriber(id, Mapping::Sender, key)
        })?;
        self.local = Some(held);
        Ok(outcome)
    }

    /// Writes a FRAME undeclaring this side's subscriber `id` on `key`.
    pub fn send_undeclare_subscriber<'a>(
        &mut self,
        id: u32,
        key: &str,
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        match self.local {
            Some(held) if held.id == id && held.key() == key.as_bytes() => {}
            _ => return Err(SessionError::UnknownSubscriber),
        }
        let outcome = self.send_frame(out, |frame| {
            frame.undeclare_subscriber(id, Mapping::Sender, key)
        })?;
        self.local = None;
        Ok(outcome)
    }

    /// Writes a FRAME carrying a Put to the key the peer declared; `attachment` is from [`encode::attachment`].
    pub fn send_put<'a>(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Outcome<'a>, SessionError> {
        match self.remote {
            Some(held) if held.key() == key.as_bytes() => {}
            _ => return Err(SessionError::UndeclaredKey),
        }
        self.send_frame(out, |frame| {
            frame.push_put(Mapping::Sender, key, attachment, payload)
        })
    }
}
