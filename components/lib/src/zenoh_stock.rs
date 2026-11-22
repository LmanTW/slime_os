//! The stock-peer exam: Profile 0 against the batches a stock eclipse-zenoh 1.0.0 peer put on a link.
//!
//! The captured bytes are `fixtures.rs`, generated from `contracts/zenoh-stock-fixtures/v1` and
//! checked against `scripts/lib/zenoh_stock_peer.py` by `just zenoh_stock_check`. This module replays
//! them into a session as listener and as connector and prints one `[zenoh-exam] stock ...` line per
//! case; `scripts/check/check-zenoh-profile0.py --slice stock` owns what those lines must be.
//!
//! The lines are checked in order within each kind, and libtest orders tests by name, so one test
//! drives every section in the order the exam lists them.

mod fixtures;

use crate::zenoh_link::{ByteLink, Link, LinkError, Notice};
use crate::zenoh_profile0::encode::{self, FrameEncoder};
use crate::zenoh_profile0::session::{Config, Event, Role, Session, SessionError, State};
use crate::zenoh_profile0::{
    GID_BYTES, MAX_ATTACHMENT_BYTES, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, Mapping,
    Message, Network, StreamFramer, decode_batch,
};
use slime_proto::zenoh_profile as p;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
/// The lease the captured stock peer announced, and the one this side announces back.
const LEASE_MS: u64 = 10_000;
const COOKIE: &[u8] = b"slime-stock-capture-cookie-01";
const ZID_OURS: [u8; 8] = [0xb2; 8];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];

fn line(text: &str) {
    println!("[zenoh-exam] stock {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write");
    }
    out
}

/// A captured batch by name, from any group.
fn captured(name: &str) -> Vec<u8> {
    fixtures::CONNECTS
        .iter()
        .chain(fixtures::LISTENS.iter())
        .chain(fixtures::REFUSE.iter())
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, bytes)| unhex(bytes))
        .unwrap_or_else(|| panic!("no captured batch named {name}"))
}

/// The refusal class name the exam pins for an error: the decoder's own, or the session's.
fn class_of(error: SessionError) -> &'static str {
    match error {
        SessionError::Decode(refusal) => refusal.name(),
        SessionError::SubscriberLimit => "subscriber-limit",
        SessionError::UnknownSubscriber => "unknown-subscriber",
        SessionError::TooManyMessages => "too-many-messages",
        SessionError::UnexpectedMessage => "unexpected-message",
        SessionError::UndeclaredKey => "undeclared-key",
        SessionError::SequenceMismatch => "sequence-mismatch",
        SessionError::CookieMismatch => "cookie-mismatch",
        SessionError::NotOpen => "not-open",
        SessionError::Closed => "closed",
        SessionError::InvalidConfig => "invalid-config",
        SessionError::Encode(_) => "encode",
        SessionError::Fragment(error) => error.class(),
        SessionError::OutOfMemory => "out-of-memory",
        SessionError::NeedsFragments => "needs-fragments",
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Handshake,
    Declared(u32),
    Sample {
        sequence: i64,
        timestamp: i64,
        payload: Vec<u8>,
    },
    Undeclared(u32),
    Closed(u8),
}

type Snapshot = (State, u32, u32, Option<u32>, Option<u32>, Option<u64>);

fn snapshot(session: &Session) -> Snapshot {
    (
        session.state(),
        session.expected_rx_sn(),
        session.next_tx_sn(),
        session.subscriber_id(),
        session.peer_subscriber_id(),
        session.lease_deadline(),
    )
}

fn owned(events: &crate::zenoh_profile0::session::Events<'_>) -> Vec<Ev> {
    events
        .iter()
        .map(|event| match *event {
            Event::HandshakeComplete => Ev::Handshake,
            Event::SubscriberDeclared { id } => Ev::Declared(id),
            Event::SampleDelivered {
                sequence,
                timestamp,
                payload,
                ..
            } => Ev::Sample {
                sequence,
                timestamp,
                payload: payload.to_vec(),
            },
            Event::SubscriberUndeclared { id } => Ev::Undeclared(id),
            Event::Closed { reason } => Ev::Closed(reason),
            Event::SampleStored { .. } => {
                unreachable!("a session that cannot fragment stores no sample")
            }
            Event::Dropped { .. } => unreachable!("a session with one run drops nothing"),
        })
        .collect()
}

/// Feeds `batch` to `session` and returns what it sent and the events it raised.
fn feed(
    session: &mut Session,
    batch: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<Ev>), SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(batch, now_ms, &mut out)?;
    Ok((outcome.batch(&out).to_vec(), owned(&outcome.events)))
}

fn feed_ok(session: &mut Session, batch: &[u8], now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    feed(session, batch, now_ms).expect("accepted")
}

/// Replays a captured batch, which must be accepted, and reports it.
fn replay(session: &mut Session, name: &str, now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    let result = feed_ok(session, &captured(name), now_ms);
    line(&format!("replay {name} ok"));
    result
}

fn listener_config() -> Config<'static> {
    Config {
        zid: &ZID_OURS,
        lease_ms: LEASE_MS,
        initial_sn: 7000,
        cookie: COOKIE,
    }
}

fn connector_config() -> Config<'static> {
    Config {
        zid: &[0xa1; 8],
        lease_ms: LEASE_MS,
        initial_sn: 9000,
        cookie: &[],
    }
}

/// Our listener, opened by the first two batches of the `connects` capture, and the time after them.
fn opened_listener() -> (Session, u64) {
    let mut ours = Session::new(Role::Listener, &listener_config()).expect("listener");
    feed_ok(&mut ours, &captured("connects-01-init-syn"), 1);
    feed_ok(&mut ours, &captured("connects-02-open-syn"), 2);
    assert!(ours.is_open());
    (ours, 3)
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The offset just past a FRAME's sequence-number varint.
fn after_sn(batch: &[u8]) -> usize {
    let mut at = 1;
    while batch[at] & 0x80 != 0 {
        at += 1;
    }
    at + 1
}

/// `batch`, a captured FRAME, carrying sequence number `sn` instead.
fn renumber(batch: &[u8], sn: u32) -> Vec<u8> {
    let mut out = vec![batch[0]];
    out.extend(leb(sn));
    out.extend(&batch[after_sn(batch)..]);
    out
}

/// Feeds `batch`, a FRAME, renumbered to the sequence number `session` expects next.
fn feed_next(
    session: &mut Session,
    batch: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<Ev>), SessionError> {
    let sn = session.expected_rx_sn();
    feed(session, &renumber(batch, sn), now_ms)
}

fn undeclare_frame(sn: u32, id: u32, key: &str) -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut out, sn).expect("frame");
    frame
        .undeclare_subscriber(id, Mapping::Sender, key)
        .expect("undeclare");
    let length = frame.finish().expect("finish");
    out[..length].to_vec()
}

fn refused(name: &str, class: &str) {
    line(&format!("refused {name} {class}"));
}

/// The four samples the demo exchanges, with their payloads and the attachment each carries.
fn samples() -> [(i64, Vec<u8>); 4] {
    [
        (0, unhex("00010000000000000a000000")),
        (1, unhex("000100000100000014000000")),
        (2, unhex("00010000020000001e000000")),
        (3, unhex("000100000300000028000000")),
    ]
}

// ---------------------------------------------------------------------------------------------
// The stock peer connects to us.

fn connects_open_and_deliver() {
    let mut ours = Session::new(Role::Listener, &listener_config()).expect("listener");
    let (ack, events) = replay(&mut ours, "connects-01-init-syn", 1);
    assert!(events.is_empty());
    assert_eq!(ours.state(), State::AwaitOpenSyn);
    assert!(matches!(decode_batch(&ack), Ok(Message::InitAck { .. })));

    let (open_ack, events) = replay(&mut ours, "connects-02-open-syn", 2);
    assert_eq!(events, [Ev::Handshake]);
    assert!(ours.is_open());
    assert_eq!(ours.peer_lease_ms(), LEASE_MS);
    assert!(matches!(
        decode_batch(&open_ack),
        Ok(Message::OpenAck { .. })
    ));

    // Our subscription on the demo key, which the stock peer's samples must match to be delivered.
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.send_declare_subscriber(1, KEY, &mut out)
        .expect("our subscriber");

    let (_, events) = replay(&mut ours, "connects-03-oam-declare-final", 3);
    assert!(events.is_empty());
    assert_eq!(ours.peer_subscriber_id(), None);
    let (_, events) = replay(
        &mut ours,
        "connects-04-declare-keyexpr-declare-subscriber",
        4,
    );
    assert_eq!(events, [Ev::Declared(1)]);
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));

    let wanted = samples();
    for (index, name) in [
        "connects-05-push-1",
        "connects-06-push-2",
        "connects-07-push-3",
        "connects-08-push-4",
    ]
    .into_iter()
    .enumerate()
    {
        // What the decoder reads from the push, in full: the session event carries no GID.
        let batch = captured(name);
        let Ok(Message::Frame(frame)) = decode_batch(&batch) else {
            panic!("{name} is not a frame");
        };
        let mut messages = frame.messages();
        let Some(Network::PushPutAlias { attachment, .. }) = messages.next() else {
            panic!("{name} is not an aliased push");
        };
        assert!(messages.next().is_none());
        assert_eq!(attachment.gid, &GID);
        line(&format!(
            "attachment {}:{} {}",
            attachment.sequence,
            attachment.timestamp,
            hex(attachment.gid)
        ));

        let (_, events) = replay(&mut ours, name, 5 + index as u64);
        let [
            Ev::Sample {
                sequence,
                timestamp,
                payload,
            },
        ] = events.as_slice()
        else {
            panic!("{name} raised {events:?}");
        };
        assert_eq!((*sequence, payload), (wanted[index].0, &wanted[index].1));
        assert_eq!(*timestamp, attachment.timestamp);
        line(&format!(
            "delivered {sequence} {} {timestamp}",
            hex(payload)
        ));
    }

    // The peer's keep-alives are traffic: they move the lease, and the session stays open.
    let (_, events) = replay(&mut ours, "connects-09-keep-alive-1", 9_000);
    assert!(events.is_empty());
    assert_eq!(ours.lease_deadline(), Some(9_000 + LEASE_MS));
    let (_, events) = replay(&mut ours, "connects-10-keep-alive-2", 11_500);
    assert!(events.is_empty());
    assert_eq!(ours.lease_deadline(), Some(11_500 + LEASE_MS));
    assert!(ours.is_open());

    let (_, events) = replay(&mut ours, "connects-11-close", 12_000);
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(ours.state(), State::Closed);
    line("ok stock-connects-open-and-deliver");
}

// ---------------------------------------------------------------------------------------------
// The stock peer listens and we connect.

fn listens_open_and_publish() {
    let mut ours = Session::new(Role::Connector, &connector_config()).expect("connector");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let init_syn = ours.connect(0, &mut out).expect("connect");
    assert!(matches!(
        decode_batch(init_syn.batch(&out)),
        Ok(Message::InitSyn { .. })
    ));
    let (open_syn, events) = replay(&mut ours, "listens-01-init-ack", 1);
    assert!(events.is_empty());
    assert_eq!(ours.state(), State::AwaitOpenAck);
    assert!(matches!(
        decode_batch(&open_syn),
        Ok(Message::OpenSyn { .. })
    ));
    let (_, events) = replay(&mut ours, "listens-02-open-ack", 2);
    assert_eq!(events, [Ev::Handshake]);
    assert!(ours.is_open());
    assert_eq!(ours.peer_lease_ms(), LEASE_MS);

    let (_, events) = replay(&mut ours, "listens-03-oam", 3);
    assert!(events.is_empty());
    let (_, events) = replay(&mut ours, "listens-04-declare-keyexpr", 4);
    assert!(events.is_empty());
    let (_, events) = replay(&mut ours, "listens-05-declare-subscriber-declare-final", 5);
    assert_eq!(events, [Ev::Declared(1)]);
    assert_eq!(ours.peer_subscriber_id(), Some(1));
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));

    // The four samples go to the key the peer declared through its alias.
    for (index, (sequence, payload)) in samples().into_iter().enumerate() {
        let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
        let before = ours.next_tx_sn();
        let outcome = ours
            .send_put(KEY, &attachment, &payload, &mut out)
            .expect("put to the declared key");
        assert_eq!(ours.next_tx_sn(), before + 1);
        let Ok(Message::Frame(frame)) = decode_batch(outcome.batch(&out)) else {
            panic!("put {index} is not a frame");
        };
        let sent: Vec<_> = frame.messages().collect();
        assert!(matches!(
            sent.as_slice(),
            [Network::PushPut { key, .. }] if *key == KEY
        ));
    }

    let (_, events) = replay(&mut ours, "listens-06-keep-alive-1", 9_000);
    assert!(events.is_empty());
    let (_, events) = replay(&mut ours, "listens-07-keep-alive-2", 11_500);
    assert!(events.is_empty());
    assert!(ours.is_open());
    let (_, events) = replay(&mut ours, "listens-08-close", 12_000);
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(ours.state(), State::Closed);
    line("ok stock-listens-open-and-publish");
}

fn alias_resolves_to_declared_key() {
    let (mut ours, now) = opened_listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.send_declare_subscriber(1, KEY, &mut out)
        .expect("ours");
    feed_next(
        &mut ours,
        &captured("connects-04-declare-keyexpr-declare-subscriber"),
        now,
    )
    .expect("accepted");
    // The subscriber declaration named the alias; the session holds the key it stands for.
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));
    // A Put addressed through the alias reaches the subscriber of the declared key, and no other.
    let (_, events) =
        feed_next(&mut ours, &captured("connects-05-push-1"), now + 1).expect("accepted");
    assert!(matches!(
        events.as_slice(),
        [Ev::Sample { sequence: 0, .. }]
    ));
    line("ok alias-resolves-to-declared-key");
}

// ---------------------------------------------------------------------------------------------
// Keep-alive and the lease.

fn handshake_pair(lease_ms: u64) -> (Session, Session) {
    let a_config = Config {
        zid: &[0xa1; 8],
        lease_ms,
        initial_sn: 100,
        cookie: &[],
    };
    let b_config = Config {
        zid: &ZID_OURS,
        lease_ms,
        initial_sn: 200,
        cookie: COOKIE,
    };
    let mut a = Session::new(Role::Connector, &a_config).expect("a");
    let mut b = Session::new(Role::Listener, &b_config).expect("b");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let init_syn = a.connect(0, &mut out).expect("connect");
    let init_syn = init_syn.batch(&out).to_vec();
    let (init_ack, _) = feed_ok(&mut b, &init_syn, 1);
    let (open_syn, _) = feed_ok(&mut a, &init_ack, 2);
    let (open_ack, _) = feed_ok(&mut b, &open_syn, 3);
    feed_ok(&mut a, &open_ack, 4);
    assert!(a.is_open() && b.is_open());
    (a, b)
}

fn keep_alive_renews_lease() {
    let (_, mut ours) = handshake_pair(LEASE_MS);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let deadline = ours.lease_deadline().expect("open");
    // The stock peer's keep-alive moves the deadline by the lease, wherever inside the lease it lands.
    feed_ok(
        &mut ours,
        &captured("connects-09-keep-alive-1"),
        deadline - 1_000,
    );
    assert_eq!(ours.lease_deadline(), Some(deadline - 1_000 + LEASE_MS));
    assert!(
        ours.tick_lease(deadline + 500, &mut out)
            .expect("tick")
            .events
            .is_empty()
    );
    assert!(ours.is_open());
    // Silence past the renewed deadline still closes it.
    let closed = ours
        .tick_lease(deadline - 1_000 + LEASE_MS + 1, &mut out)
        .expect("tick");
    assert_eq!(ours.state(), State::Closed);
    assert_eq!(closed.events.len(), 1);
    line("ok keep-alive-renews-lease");
}

/// A session that has sent nothing for a quarter of the peer's lease writes a KEEP_ALIVE, and
/// again a quarter later.
fn keep_alive_cadence(lease_ms: u64, name: &str) {
    let (mut a, mut b) = handshake_pair(lease_ms);
    let quarter = lease_ms / 4;
    let mut out = [0u8; MAX_BATCH_BYTES];
    // `b` last sent at 3, with its OPEN_ACK.
    let first = 3 + quarter;
    assert_eq!(b.keep_alive_due(), first);
    let quiet = b.tick(first - 1, &mut out).expect("tick");
    assert_eq!(quiet.sent, 0, "{name}: nothing is due yet");
    let due = b.tick(first, &mut out).expect("tick");
    assert_eq!(
        due.batch(&out),
        [0x04],
        "{name}: the keep-alive is the single byte 04"
    );
    assert_eq!(decode_batch(due.batch(&out)), Ok(Message::KeepAlive));
    // The next one is a quarter after it, not sooner.
    assert_eq!(b.keep_alive_due(), first + quarter);
    assert_eq!(b.tick(first + quarter - 1, &mut out).expect("tick").sent, 0);
    assert_eq!(b.tick(first + quarter, &mut out).expect("tick").sent, 1);
    // The peer takes it as traffic, which moves its lease.
    feed_ok(&mut a, &[0x04], first);
    assert_eq!(a.lease_deadline(), Some(first + lease_ms));
    assert!(a.is_open());
    line(&format!("ok {name}"));
}

fn silence_past_lease_closes() {
    let (mut a, mut b) = handshake_pair(2_000);
    let mut out = [0u8; MAX_BATCH_BYTES];
    // `b` last heard from `a` at 3 (its OPEN_SYN), so the lease runs out after 2003.
    assert_eq!(b.lease_deadline(), Some(2_003));
    assert!(
        b.tick_lease(2_003, &mut out)
            .expect("tick")
            .events
            .is_empty()
    );
    assert!(b.is_open());
    let expired = b.tick(2_004, &mut out).expect("tick");
    assert_eq!(owned(&expired.events), [Ev::Closed(p::CLOSE_EXPIRED as u8)]);
    assert_eq!(b.state(), State::Closed);
    let close = expired.batch(&out).to_vec();
    assert_eq!(
        decode_batch(&close),
        Ok(Message::Close {
            reason: p::CLOSE_EXPIRED as u8,
            session: true
        })
    );
    let (_, events) = feed_ok(&mut a, &close, 2_005);
    assert_eq!(events, [Ev::Closed(p::CLOSE_EXPIRED as u8)]);
    line("ok silence-past-lease-closes");
}

/// Nothing is sent on a tick before OPEN, whatever the time between a quarter lease and the lease.
fn tick_silent(name: &str, session: &mut Session, entered_ms: u64) {
    let before = snapshot(session);
    let mut out = [0u8; MAX_BATCH_BYTES];
    for offset in [LEASE_MS / 4, LEASE_MS / 2, LEASE_MS] {
        let outcome = session.tick(entered_ms + offset, &mut out).expect("tick");
        assert_eq!(outcome.sent, 0, "{name} sent something at +{offset}");
        assert!(
            outcome.events.is_empty(),
            "{name} raised events at +{offset}"
        );
        assert_eq!(snapshot(session), before, "{name} changed at +{offset}");
    }
    line(&format!("ok {name}"));
}

/// The sessions of each state before OPEN, with the time each was entered.
fn before_open() -> [(&'static str, Session, u64); 4] {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let idle = Session::new(Role::Listener, &listener_config()).expect("idle");

    let mut connector = Session::new(Role::Connector, &connector_config()).expect("connector");
    connector.connect(10, &mut out).expect("connect");

    let mut awaiting_open_syn = Session::new(Role::Listener, &listener_config()).expect("listener");
    feed_ok(
        &mut awaiting_open_syn,
        &captured("connects-01-init-syn"),
        10,
    );

    let mut awaiting_open_ack =
        Session::new(Role::Connector, &connector_config()).expect("connector");
    awaiting_open_ack.connect(0, &mut out).expect("connect");
    feed_ok(&mut awaiting_open_ack, &captured("listens-01-init-ack"), 10);

    [
        ("tick-silent-in-idle", idle, 10),
        ("tick-silent-while-awaiting-init-ack", connector, 10),
        ("tick-silent-while-awaiting-open-syn", awaiting_open_syn, 10),
        ("tick-silent-while-awaiting-open-ack", awaiting_open_ack, 10),
    ]
}

// A scripted byte stream between two links.

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    tx: Rc<RefCell<Pipe>>,
    send_cap: Rc<Cell<Option<usize>>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let take = self
            .send_cap
            .get()
            .map_or(buf.len(), |cap| cap.min(buf.len()));
        self.tx.borrow_mut().bytes.extend(buf.iter().take(take));
        Ok(take)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        let mut pipe = self.rx.borrow_mut();
        let mut count = 0;
        while count < buf.len() {
            match pipe.bytes.pop_front() {
                Some(byte) => {
                    buf[count] = byte;
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }

    fn eof(&self) -> bool {
        false
    }
}

/// An ordinary batch at a quarter-lease boundary adds no KEEP_ALIVE: it goes out whole, the
/// cadence restarts from it, and the link stays open.
fn keep_alive_suppressed_by_traffic() {
    let a_to_b = Rc::new(RefCell::new(Pipe::default()));
    let b_to_a = Rc::new(RefCell::new(Pipe::default()));
    let a_cap = Rc::new(Cell::new(None));
    let b_cap = Rc::new(Cell::new(None));
    let lease = 2_000;
    let quarter = lease / 4;
    let config = |zid: &'static [u8], cookie: &'static [u8], initial_sn| Config {
        zid,
        lease_ms: lease,
        initial_sn,
        cookie,
    };
    let mut a = Link::new(
        Scripted {
            rx: b_to_a.clone(),
            tx: a_to_b.clone(),
            send_cap: a_cap.clone(),
        },
        Role::Connector,
        &config(&[0xa1, 0xa2], b"", 100),
        1,
    )
    .expect("a");
    let mut b = Link::new(
        Scripted {
            rx: a_to_b.clone(),
            tx: b_to_a.clone(),
            send_cap: b_cap,
        },
        Role::Listener,
        &config(&[0xb1, 0xb2], b"cookie-b", 200),
        1,
    )
    .expect("b");
    let (ha, hb) = (a.handle(), b.handle());
    let settle = |a: &mut Link<Scripted>, b: &mut Link<Scripted>, now: u64| {
        for _ in 0..400 {
            let x = a.pump(ha, now).expect("a pump");
            let y = b.pump(hb, now).expect("b pump");
            if x.batches + y.batches + x.sent_bytes + y.sent_bytes == 0
                && !a.send_pending()
                && !b.send_pending()
            {
                return;
            }
        }
        panic!("the pair did not settle");
    };
    a.open(ha, 0).expect("open");
    settle(&mut a, &mut b, 0);
    assert!(a.is_open() && b.is_open());
    b.declare_subscriber(hb, 1, KEY).expect("declare");
    settle(&mut a, &mut b, 1);
    // `a` sent its OPEN_SYN at 0, so its first keep-alive is due at one quarter lease.
    assert_eq!(a.session().keep_alive_due(), quarter);

    // At the boundary `a` has a batch to send and its stream will not take it: the batch stays
    // queued whole, and no keep-alive is added beside it.
    a_cap.set(Some(0));
    let attachment = encode::attachment(1, 1_001, &GID).expect("attachment");
    a.publish(ha, KEY, &attachment, &samples()[0].1)
        .expect("publish");
    a.pump(ha, quarter).expect("pump at the boundary");
    assert!(a.send_pending(), "the batch is still waiting");
    assert!(a_to_b.borrow().bytes.is_empty(), "nothing reached the wire");
    assert!(a.is_open() && !a.is_closed());

    // Once the stream takes it, the batch goes out whole and the cadence restarts from it.
    a_cap.set(None);
    a.pump(ha, quarter + 20).expect("pump after the stall");
    assert!(!a.send_pending());
    let mut framer = StreamFramer::new();
    let put_wire: Vec<u8> = a_to_b.borrow_mut().bytes.drain(..).collect();
    assert_eq!(framer.push(&put_wire), put_wire.len());
    let batch = framer
        .peek_batch()
        .expect("prefix")
        .expect("a whole batch")
        .to_vec();
    assert!(
        matches!(decode_batch(&batch), Ok(Message::Frame(_))),
        "the put, not a keep-alive"
    );
    framer.consume_batch();
    assert_eq!(framer.pending(), 0, "no keep-alive beside it");
    assert_eq!(a.session().keep_alive_due(), quarter + 20 + quarter);

    // A quarter after that batch the link is quiet, and the keep-alive comes.
    a.pump(ha, quarter + 20 + quarter - 1).expect("pump");
    assert!(a_to_b.borrow().bytes.is_empty());
    a.pump(ha, quarter + 20 + quarter)
        .expect("pump at the new boundary");
    let wire: Vec<u8> = a_to_b.borrow_mut().bytes.drain(..).collect();
    assert_eq!(wire, [0x01, 0x00, 0x04], "a framed KEEP_ALIVE");
    // What was read off the wire for inspection goes back, in order, for the peer to take.
    a_to_b
        .borrow_mut()
        .bytes
        .extend(put_wire.iter().chain(wire.iter()));
    settle(&mut a, &mut b, quarter + 21);
    let mut delivered = 0;
    while let Some(notice) = b.next_notice() {
        if matches!(notice, Notice::SampleDelivered(_)) {
            delivered += 1;
        }
    }
    assert_eq!(delivered, 1);
    line("ok keep-alive-suppressed-by-traffic");
}

// ---------------------------------------------------------------------------------------------
// What a bounded profile still refuses.

fn refusals() {
    // The captured refusals, through an open session that must come out unchanged.
    let (mut ours, now) = opened_listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.send_declare_subscriber(1, KEY, &mut out)
        .expect("ours");
    let sn = ours.expected_rx_sn();
    feed_ok(
        &mut ours,
        &renumber(
            &captured("connects-04-declare-keyexpr-declare-subscriber"),
            sn,
        ),
        now,
    );
    for (name, _) in fixtures::REFUSE {
        let before = snapshot(&ours);
        let error = feed(&mut ours, &captured(name), now + 1).expect_err(name);
        assert_eq!(snapshot(&ours), before, "{name} changed the session");
        refused(name, class_of(error));
    }

    // Aliases.
    let (mut ours, now) = opened_listener();
    ours.send_declare_subscriber(1, KEY, &mut out)
        .expect("ours");
    let declare_key = captured("listens-04-declare-keyexpr");
    let alias_subscriber = captured("listens-05-declare-subscriber-declare-final");
    let before = snapshot(&ours);
    let error = feed_next(&mut ours, &alias_subscriber, now).expect_err("undeclared");
    assert_eq!(snapshot(&ours), before);
    refused("alias-undeclared", class_of(error));
    let error = feed_next(&mut ours, &captured("connects-05-push-1"), now).expect_err("put");
    assert_eq!(class_of(error), "invalid-keyexpr");

    feed_next(&mut ours, &declare_key, now).expect("accepted");
    let before = snapshot(&ours);
    let marker = [0x20, 0x01, 0x00, 0x81, 0x01];
    let at = declare_key
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("DeclareKeyExpr");
    let mut second = declare_key.clone();
    second[at + 1] = 0x02;
    let error = feed_next(&mut ours, &second, now).expect_err("second");
    assert_eq!(snapshot(&ours), before);
    refused("alias-second", class_of(error));
    let mut other_key = declare_key.clone();
    let last = other_key.len() - 1;
    other_key[last] = b'c';
    let error = feed_next(&mut ours, &other_key, now).expect_err("other key");
    assert_eq!(snapshot(&ours), before);
    refused("alias-redeclared-to-other-key", class_of(error));
    let error = feed_next(&mut ours, &declare_key, now).expect_err("same key");
    assert_eq!(snapshot(&ours), before);
    refused("alias-redeclared-same-key", class_of(error));

    // The single subscriber slot, in both directions.
    feed_next(&mut ours, &alias_subscriber, now).expect("accepted");
    assert_eq!(ours.peer_subscriber_id(), Some(1));
    let before = snapshot(&ours);
    let error = feed_next(&mut ours, &alias_subscriber, now).expect_err("second subscriber");
    assert_eq!(snapshot(&ours), before);
    refused("second-subscriber-received", class_of(error));
    let error = ours
        .send_declare_subscriber(2, KEY, &mut out)
        .expect_err("sent twice");
    assert_eq!(snapshot(&ours), before);
    refused("second-subscriber-sent", class_of(error));

    // Undeclaring a subscriber the session does not hold, in both directions, leaves the held one.
    for (id, key) in [(2, KEY), (1, "0/other")] {
        let error = feed_next(&mut ours, &undeclare_frame(0, id, key), now).expect_err("undeclare");
        assert_eq!(snapshot(&ours), before);
        assert_eq!(class_of(error), "unknown-subscriber");
    }
    let error = feed_next(&mut ours, &undeclare_frame(0, 3, KEY), now).expect_err("undeclare");
    assert_eq!(snapshot(&ours), before);
    refused("unknown-subscriber-received", class_of(error));
    for (id, key) in [(2, KEY), (1, "0/other")] {
        let error = ours
            .send_undeclare_subscriber(id, key, &mut out)
            .expect_err("undeclare");
        assert_eq!(snapshot(&ours), before);
        assert_eq!(class_of(error), "unknown-subscriber");
    }
    let error = ours
        .send_undeclare_subscriber(3, KEY, &mut out)
        .expect_err("undeclare");
    assert_eq!(snapshot(&ours), before);
    refused("unknown-subscriber-sent", class_of(error));

    // One FRAME yields at most four events: five aliased PUSHes are refused, none dropped.
    let push = captured("connects-05-push-1");
    let body = &push[after_sn(&push)..];
    let mut five = vec![push[0]];
    five.extend(leb(ours.expected_rx_sn()));
    for _ in 0..5 {
        five.extend(body);
    }
    let error = feed(&mut ours, &five, now).expect_err("five events");
    assert_eq!(snapshot(&ours), before);
    refused("frame-five-events", class_of(error));

    // KEEP_ALIVE is exactly the single byte 04.
    let error = feed(&mut ours, &[0x04, 0x00], now).expect_err("trailing byte");
    assert_eq!(snapshot(&ours), before);
    refused("keep-alive-trailing-byte", class_of(error));
    // ... and is traffic only on an open session.
    for (name, mut session, entered) in before_open() {
        let state = snapshot(&session);
        let error = feed(&mut session, &[0x04], entered + 1).expect_err(name);
        assert_eq!(snapshot(&session), state, "{name} changed the session");
        let name = name.replace("tick-silent", "keep-alive");
        refused(&name, class_of(error));
    }

    // Extensions: only the optional QoS where it was seen.
    let init_syn = captured("connects-01-init-syn");
    let mut other = init_syn.clone();
    *other.last_mut().expect("extension byte") = 0x02;
    let mut mandatory = init_syn;
    *mandatory.last_mut().expect("extension byte") = 0x11;
    let mut qos_on_open = captured("connects-02-open-syn");
    qos_on_open[0] |= 0x80;
    qos_on_open.push(0x01);
    let mut qos_on_init_ack = captured("listens-01-init-ack");
    qos_on_init_ack[0] |= 0x80;
    qos_on_init_ack.push(0x01);
    let mut network_mandatory = declare_key.clone();
    let at = network_mandatory
        .windows(3)
        .position(|window| window == [0x9e, 0x21, 0x08])
        .expect("QoS on the outer DECLARE");
    network_mandatory[at + 1] = 0x31;
    let before = snapshot(&ours);
    for (name, batch) in [
        ("extension-other-than-qos", other),
        ("transport-qos-marked-mandatory", mandatory),
        ("network-qos-marked-mandatory", network_mandatory),
        ("qos-extension-on-open", qos_on_open),
        ("qos-extension-on-init-ack", qos_on_init_ack),
    ] {
        let error = feed(&mut ours, &batch, now).expect_err(name);
        assert_eq!(snapshot(&ours), before);
        refused(name, class_of(error));
    }
}

// ---------------------------------------------------------------------------------------------
// The decoder's properties, on the batches the corpus does not hold.

fn bounded(frame: &crate::zenoh_profile0::Frame<'_>) {
    for message in frame.messages() {
        match message {
            Network::DeclareSubscriber { key, .. }
            | Network::UndeclareSubscriber { key, .. }
            | Network::DeclareKeyExpr { key, .. } => assert!(key.len() <= MAX_KEY_BYTES),
            Network::PushPut {
                key,
                attachment,
                payload,
                ..
            } => {
                assert!(key.len() <= MAX_KEY_BYTES);
                assert_eq!(attachment.raw.len(), MAX_ATTACHMENT_BYTES);
                assert_eq!(attachment.gid.len(), GID_BYTES);
                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
            }
            Network::PushPutAlias {
                attachment,
                payload,
                ..
            } => {
                assert_eq!(attachment.raw.len(), MAX_ATTACHMENT_BYTES);
                assert_eq!(attachment.gid.len(), GID_BYTES);
                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
            }
            Network::DeclareSubscriberAlias { .. }
            | Network::UndeclareSubscriberById { .. }
            | Network::Oam
            | Network::DeclareFinal => {}
        }
    }
}

/// No proper prefix is accepted unless it is a shorter frame, a flipped bit never panics or
/// exceeds a bound, and every two-chunk split of the framed batch reassembles to it.
fn properties(name: &str, batch: &[u8]) {
    let whole = match decode_batch(batch) {
        Ok(Message::Frame(frame)) => Some(frame.messages().count()),
        Ok(_) => None,
        Err(refusal) => panic!("{name} is not accepted: {refusal:?}"),
    };
    for length in 0..batch.len() {
        match decode_batch(&batch[..length]) {
            Err(_) => {}
            Ok(Message::Frame(frame)) => {
                let total = whole.unwrap_or_else(|| {
                    panic!("{name}: a non-frame decoded a {length}-byte prefix")
                });
                assert!(
                    frame.messages().count() < total,
                    "{name}: a {length}-byte prefix decoded as much as the whole"
                );
            }
            Ok(_) => panic!("{name}: a {length}-byte prefix decoded"),
        }
    }
    for position in 0..batch.len() {
        for flip in [0x01u8, 0x80] {
            let mut mutated = batch.to_vec();
            mutated[position] ^= flip;
            if let Ok(Message::Frame(frame)) = decode_batch(&mutated) {
                bounded(&frame);
            }
        }
    }
    let mut framed = (batch.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(batch);
    for cut in 1..framed.len() {
        let mut framer = StreamFramer::new();
        assert_eq!(framer.push(&framed[..cut]), cut);
        if cut >= framed.len() {
            continue;
        }
        if let Ok(Some(_)) = framer.peek_batch() {
            panic!("{name}: complete before its last byte at {cut}");
        }
        assert_eq!(framer.push(&framed[cut..]), framed.len() - cut);
        assert_eq!(
            framer.peek_batch().expect("prefix"),
            Some(batch),
            "{name} split at {cut}"
        );
        framer.consume_batch();
        assert_eq!(framer.pending(), 0);
    }
    line(&format!("property {name} ok"));
}

#[test]
fn the_cookie_is_the_captured_one() {
    assert_eq!(fixtures::COOKIE_HEX, hex(COOKIE));
    assert_eq!(fixtures::FORMAT_VERSION, 1);
}

/// An alias the peer declared is in the peer's own mapping. A reference that clears the sender bit
/// names an alias this side declared, and this side declares none, so it is not resolved.
#[test]
fn an_alias_in_the_receiver_mapping_is_not_resolved() {
    let declare = captured("connects-04-declare-keyexpr-declare-subscriber");
    // The batch ends with the DeclareSubscriber body `42 01 01`; clearing bit 6 of the inner
    // header makes its key reference receiver-mapped.
    let tail = declare.len() - 3;
    assert_eq!(&declare[tail..], &[0x42, 0x01, 0x01]);
    let mut receiver_subscriber = declare.clone();
    receiver_subscriber[tail] = 0x02;
    let (mut ours, now) = opened_listener();
    assert_eq!(
        feed_next(&mut ours, &receiver_subscriber, now)
            .expect_err("a receiver-mapped alias subscriber"),
        SessionError::Decode(crate::zenoh_profile0::Refusal::InvalidKeyexpr)
    );
    assert_eq!(ours.peer_subscriber_key(), None);

    let (mut ours, now) = opened_listener();
    feed_next(&mut ours, &declare, now).expect("the captured declaration");
    let mut receiver_put = captured("connects-05-push-1");
    let at = after_sn(&receiver_put);
    assert_eq!(receiver_put[at], 0x5d);
    receiver_put[at] = 0x1d;
    assert_eq!(
        feed_next(&mut ours, &receiver_put, now + 1).expect_err("a receiver-mapped alias put"),
        SessionError::Decode(crate::zenoh_profile0::Refusal::InvalidKeyexpr)
    );
}

/// The captured alias declaration alone, with the id the capture used replaced by `id`.
fn declaration_with_id(id: &[u8]) -> Vec<u8> {
    let declare = captured("connects-04-declare-keyexpr-declare-subscriber");
    // After the outer QoS extension the batch holds the DeclareKeyExpr header `20`, id `01`,
    // scope `00`, the key length `81 01` and the 129 key bytes, then the subscriber declaration.
    let head = [0x20, 0x01, 0x00, 0x81, 0x01];
    let at = declare
        .windows(head.len())
        .position(|window| window == head)
        .expect("the captured declaration");
    let end = at + head.len() + 129;
    let mut batch = declare[..at + 1].to_vec();
    batch.extend_from_slice(id);
    batch.extend_from_slice(&declare[at + 2..end]);
    batch
}

/// An alias id is the 16-bit scope every reference to it carries. One the references cannot
/// express is refused when it is declared, so it never takes the only alias slot.
#[test]
fn an_alias_id_wider_than_a_reference_is_refused_at_its_declaration() {
    let declare = captured("connects-04-declare-keyexpr-declare-subscriber");
    // 65535 is the largest id a reference can name and is accepted.
    let (mut ours, now) = opened_listener();
    feed_next(&mut ours, &declaration_with_id(&[0xff, 0xff, 0x03]), now).expect("alias 65535");
    // 65536 is not: it is refused at its declaration and leaves the one alias slot free.
    let (mut ours, now) = opened_listener();
    let refused = feed_next(&mut ours, &declaration_with_id(&[0x80, 0x80, 0x04]), now)
        .expect_err("an alias id of 65536");
    assert_eq!(
        refused,
        SessionError::Decode(crate::zenoh_profile0::Refusal::Leb128Overflow)
    );
    feed_next(&mut ours, &declare, now).expect("the slot was not consumed");
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));
}

/// Scope 0 is the global scope, so a reference with it names no alias: id 0 could never be
/// referenced and is refused when declared, leaving the one alias slot free.
#[test]
fn alias_id_zero_is_refused_at_its_declaration() {
    let declare = captured("connects-04-declare-keyexpr-declare-subscriber");
    let (mut ours, now) = opened_listener();
    let refused =
        feed_next(&mut ours, &declaration_with_id(&[0x00]), now).expect_err("an alias id of 0");
    assert_eq!(
        refused,
        SessionError::Decode(crate::zenoh_profile0::Refusal::InvalidKeyexpr)
    );
    feed_next(&mut ours, &declare, now).expect("the slot was not consumed");
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));
}

/// When the exam hands over its validated record, the generated constants are exactly that record:
/// the same cookie, the same groups, the same names and bytes in the same order. A constant that
/// drifted from the checker's captured bytes fails here instead of replaying stale bytes. Without
/// the variable, a plain `cargo test`, there is no record to compare and nothing is asserted.
#[test]
fn the_constants_are_the_handed_off_record() {
    let Some(path) = std::env::var_os("ZENOH_STOCK_FIXTURES") else {
        return;
    };
    let record = std::fs::read_to_string(&path).expect("the hand-off record is readable");
    let mut wanted = String::new();
    wanted.push_str("{\n");
    wanted.push_str(&format!(
        "  formatVersion = {};\n",
        fixtures::FORMAT_VERSION
    ));
    wanted.push_str(&format!("  cookieHex = \"{}\";\n", fixtures::COOKIE_HEX));
    for (group, rows) in [
        ("connects", &fixtures::CONNECTS[..]),
        ("listens", &fixtures::LISTENS[..]),
        ("refuse", &fixtures::REFUSE[..]),
    ] {
        wanted.push_str(&format!("  {group} = [\n"));
        for (name, bytes) in rows {
            wanted.push_str(&format!(
                "    {{ name = \"{name}\"; hex = \"{bytes}\"; }};\n"
            ));
        }
        wanted.push_str("  ];\n");
    }
    wanted.push_str("}\n");
    assert_eq!(
        record, wanted,
        "fixtures.rs differs from the record the exam handed over; run `just zenoh_stock_gen`"
    );
}

/// Every section, in the order the exam lists them.
#[test]
fn the_stock_peer_exam() {
    connects_open_and_deliver();
    listens_open_and_publish();
    alias_resolves_to_declared_key();
    keep_alive_renews_lease();
    keep_alive_cadence(2_000, "keep-alive-sent-lease-2000");
    keep_alive_cadence(10_000, "keep-alive-sent-lease-10000");
    silence_past_lease_closes();
    for (name, mut session, entered) in before_open() {
        tick_silent(name, &mut session, entered);
    }
    keep_alive_suppressed_by_traffic();
    refusals();
    for (name, bytes) in fixtures::CONNECTS.iter().chain(fixtures::LISTENS.iter()) {
        properties(name, &unhex(bytes));
    }
}
