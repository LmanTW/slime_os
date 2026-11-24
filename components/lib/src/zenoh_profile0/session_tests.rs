//! Host tests for the Zenoh Profile 0 session state machine.
//!
//! A connector and a listener are driven against each other through
//! `StreamFramer` and `decode_batch`. The `[zenoh-exam] session` lines are what
//! `scripts/check/check-zenoh-profile0.py --slice session` reads; each is
//! printed only after its scenario's assertions passed.

use super::*;
use crate::zenoh_profile0::encode::{self, FrameEncoder, stream_batch};
use crate::zenoh_profile0::{Mapping, Message, Network, StreamFramer, decode_batch};
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const PAYLOADS: [&str; 4] = [
    "00010000000000000a000000",
    "000100000100000014000000",
    "00010000020000001e000000",
    "000100000300000028000000",
];
const LEASE_MS: u64 = 2000;
const CONNECTOR_SN: u32 = u32::MAX - 1;
const LISTENER_SN: u32 = 7000;
const ZID_CONNECTOR: [u8; 8] = [0xa1; 8];
const ZID_LISTENER: [u8; 8] = [0xb2; 8];

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

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn cookie() -> [u8; 32] {
    core::array::from_fn(|at| 0xc0 + at as u8)
}

fn gid() -> [u8; 16] {
    core::array::from_fn(|at| 0xe0 + at as u8)
}

fn connector() -> Session {
    let config = Config {
        zid: &ZID_CONNECTOR,
        lease_ms: LEASE_MS,
        initial_sn: CONNECTOR_SN,
        cookie: &[],
    };
    Session::new(Role::Connector, &config).expect("connector")
}

fn listener() -> Session {
    let cookie = cookie();
    let config = Config {
        zid: &ZID_LISTENER,
        lease_ms: LEASE_MS,
        initial_sn: LISTENER_SN,
        cookie: &cookie,
    };
    Session::new(Role::Listener, &config).expect("listener")
}

fn owned(outcome: &Outcome<'_>, out: &[u8]) -> (Vec<u8>, Vec<Ev>) {
    let events = outcome
        .events
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
            Event::Dropped { .. } => unreachable!("these sessions hold one run and drop nothing"),
            Event::QueryableDeclared { .. }
            | Event::QueryableUndeclared { .. }
            | Event::QueryReceived { .. }
            | Event::ReplyDelivered { .. }
            | Event::QueryFinished { .. } => unreachable!("this exam carries no query"),
        })
        .collect();
    (outcome.batch(out).to_vec(), events)
}

/// Frames `batch` onto a byte stream delivered in small chunks and returns the framer.
fn streamed(batch: &[u8]) -> StreamFramer {
    let mut wire = [0u8; MAX_BATCH_BYTES + 2];
    let total = stream_batch(&mut wire, batch).expect("stream");
    let mut framer = StreamFramer::new();
    for chunk in wire[..total].chunks(7) {
        assert_eq!(framer.push(chunk), chunk.len());
    }
    framer
}

/// Delivers one batch to `session` through the stream framer and the decoder.
fn recv(
    session: &mut Session,
    batch: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<Ev>), SessionError> {
    let framer = streamed(batch);
    let body = framer.peek_batch().expect("prefix").expect("complete");
    assert_eq!(body, batch);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(body, now_ms, &mut out)?;
    Ok(owned(&outcome, &out))
}

fn expect_recv(session: &mut Session, batch: &[u8], now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    recv(session, batch, now_ms).expect("accepted")
}

fn snapshot(session: &Session) -> (State, u32, u32, Option<u32>, Option<u64>) {
    (
        session.state(),
        session.expected_rx_sn(),
        session.next_tx_sn(),
        session.subscriber_id(),
        session.lease_deadline(),
    )
}

/// Runs the full handshake and returns the open pair.
fn handshake() -> (Session, Session) {
    let mut a = connector();
    let mut b = listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = a.connect(0, &mut out).expect("connect");
    let (init_syn, events) = owned(&outcome, &out);
    assert!(events.is_empty());
    assert_eq!(a.state(), State::AwaitInitAck);

    let (init_ack, events) = expect_recv(&mut b, &init_syn, 1);
    assert!(events.is_empty());
    assert_eq!(b.state(), State::AwaitOpenSyn);

    let (open_syn, events) = expect_recv(&mut a, &init_ack, 2);
    assert!(events.is_empty());
    assert_eq!(a.state(), State::AwaitOpenAck);

    let (open_ack, events) = expect_recv(&mut b, &open_syn, 3);
    assert_eq!(events, [Ev::Handshake]);
    assert!(b.is_open());

    let (nothing, events) = expect_recv(&mut a, &open_ack, 4);
    assert!(nothing.is_empty());
    assert_eq!(events, [Ev::Handshake]);
    assert!(a.is_open());
    (a, b)
}

/// `b` is the subscriber: it declares its subscription and `a`, the publisher, learns of it.
fn declare(a: &mut Session, b: &mut Session, id: u32, now_ms: u64) {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = b.send_declare_subscriber(id, KEY, &mut out).expect("send");
    let (frame, _) = owned(&outcome, &out);
    let (reply, events) = expect_recv(a, &frame, now_ms);
    assert!(reply.is_empty());
    assert_eq!(events, [Ev::Declared(id)]);
}

fn put_frame(sn: u32, key: &str, sequence: i64) -> Vec<u8> {
    let attachment = encode::attachment(sequence, 0, &gid()).expect("attachment");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut out, sn).expect("frame");
    frame
        .push_put(Mapping::Receiver, key, &attachment, &[1, 2, 3])
        .expect("put");
    let length = frame.finish().expect("finish");
    out[..length].to_vec()
}

fn patch(batch: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let at = batch
        .windows(from.len())
        .position(|window| window == from)
        .expect("pattern");
    batch[at..at + to.len()].copy_from_slice(to);
}

#[test]
fn connect_handshake() {
    let (a, b) = handshake();
    assert_eq!(a.role(), Role::Connector);
    assert_eq!(b.role(), Role::Listener);
    assert_eq!(a.peer_lease_ms(), LEASE_MS);
    assert_eq!(b.peer_lease_ms(), LEASE_MS);
    assert_eq!(a.expected_rx_sn(), LISTENER_SN);
    assert_eq!(b.expected_rx_sn(), CONNECTOR_SN);
    assert_eq!(a.subscriber_id(), None);
    println!("[zenoh-exam] session ok connect-handshake");
}

#[test]
fn listen_handshake() {
    let mut b = listener();
    assert_eq!(b.state(), State::Idle);
    let mut a = connector();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = a.connect(10, &mut out).expect("connect");
    let (init_syn, _) = owned(&outcome, &out);
    assert_eq!(
        decode_batch(&init_syn),
        Ok(Message::InitSyn {
            zid: &ZID_CONNECTOR,
            batch_size: 512,
            qos: false
        })
    );
    let (init_ack, _) = expect_recv(&mut b, &init_syn, 11);
    match decode_batch(&init_ack) {
        Ok(Message::InitAck {
            zid,
            batch_size,
            cookie: sent,
            ..
        }) => {
            assert_eq!(zid, ZID_LISTENER);
            assert_eq!(batch_size, 512);
            assert_eq!(sent, cookie());
        }
        other => panic!("expected INIT_ACK, got {other:?}"),
    }
    let (open_syn, _) = expect_recv(&mut a, &init_ack, 12);
    assert_eq!(
        decode_batch(&open_syn),
        Ok(Message::OpenSyn {
            lease_ms: LEASE_MS,
            initial_sn: CONNECTOR_SN,
            cookie: &cookie()
        })
    );
    let (open_ack, events) = expect_recv(&mut b, &open_syn, 13);
    assert_eq!(events, [Ev::Handshake]);
    assert_eq!(
        decode_batch(&open_ack),
        Ok(Message::OpenAck {
            lease_ms: LEASE_MS,
            initial_sn: LISTENER_SN
        })
    );
    assert!(b.is_open());
    assert_eq!(b.expected_rx_sn(), CONNECTOR_SN);
    println!("[zenoh-exam] session ok listen-handshake");
}

#[test]
fn declare_then_push_delivered() {
    let (mut a, mut b) = handshake();
    declare(&mut a, &mut b, 1, 10);
    assert_eq!(b.subscriber_id(), Some(1));
    assert_eq!(b.subscriber_key(), Some(KEY));
    assert_eq!(a.peer_subscriber_id(), Some(1));
    assert_eq!(a.peer_subscriber_key(), Some(KEY));

    for (index, payload) in PAYLOADS.iter().enumerate() {
        let sequence = index as i64;
        let timestamp = 1_000 + sequence;
        let attachment = encode::attachment(sequence, timestamp, &gid()).expect("attachment");
        assert_eq!(attachment.len(), 33);
        let payload = unhex(payload);
        let mut out = [0u8; MAX_BATCH_BYTES];
        let outcome = a
            .send_put(KEY, &attachment, &payload, &mut out)
            .expect("send");
        let (frame, _) = owned(&outcome, &out);
        let (reply, events) = expect_recv(&mut b, &frame, 20 + sequence as u64);
        assert!(reply.is_empty());
        assert_eq!(
            events,
            [Ev::Sample {
                sequence,
                timestamp,
                payload
            }]
        );
    }
    // The subscriber's declare frame travelled the other way, so b's receive side saw only the
    // four samples: they carry CONNECTOR_SN.. and cross the u32 wrap.
    assert_eq!(b.expected_rx_sn(), CONNECTOR_SN.wrapping_add(4));
    assert_eq!(b.expected_rx_sn(), 2);
    println!("[zenoh-exam] session ok declare-then-push-delivered");
}

#[test]
fn teardown_undeclare_then_close() {
    let (mut a, mut b) = handshake();
    declare(&mut a, &mut b, 1, 10);

    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = b.send_undeclare_subscriber(1, KEY, &mut out).expect("send");
    let (frame, _) = owned(&outcome, &out);
    let (_, events) = expect_recv(&mut a, &frame, 11);
    assert_eq!(events, [Ev::Undeclared(1)]);
    assert_eq!(b.subscriber_id(), None);
    assert_eq!(a.peer_subscriber_id(), None);
    assert!(a.is_open() && b.is_open());

    let outcome = a.close(0, &mut out).expect("close");
    let (close, events) = owned(&outcome, &out);
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(a.state(), State::Closed);
    assert_eq!(
        decode_batch(&close),
        Ok(Message::Close {
            reason: 0,
            session: true
        })
    );
    let (reply, events) = expect_recv(&mut b, &close, 12);
    assert!(reply.is_empty());
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.subscriber_id(), None);

    let put = put_frame(b.expected_rx_sn(), KEY, 0);
    assert_eq!(recv(&mut b, &put, 13).err(), Some(SessionError::Closed));
    println!("[zenoh-exam] session ok teardown-undeclare-then-close");
}

#[test]
fn lease_expiry_closes() {
    let (mut a, mut b) = handshake();
    let mut out = [0u8; MAX_BATCH_BYTES];
    assert_eq!(b.lease_deadline(), Some(3 + LEASE_MS));

    let quiet = b.tick_lease(3 + LEASE_MS, &mut out).expect("tick");
    assert_eq!(quiet.sent, 0);
    assert!(quiet.events.is_empty());
    assert!(b.is_open());

    // A received batch moves the deadline: a's declaration travels to b as a FRAME from a.
    let mut sent = [0u8; MAX_BATCH_BYTES];
    let outcome = a.send_declare_subscriber(1, KEY, &mut sent).expect("send");
    let (frame, _) = owned(&outcome, &sent);
    let (_, events) = expect_recv(&mut b, &frame, 1500);
    assert_eq!(events, [Ev::Declared(1)]);
    assert_eq!(b.lease_deadline(), Some(1500 + LEASE_MS));
    assert!(
        b.tick_lease(3500, &mut out)
            .expect("tick")
            .events
            .is_empty()
    );
    assert!(b.is_open());

    let outcome = b.tick_lease(3501, &mut out).expect("tick");
    let (close, events) = owned(&outcome, &out);
    assert_eq!(events, [Ev::Closed(p::CLOSE_EXPIRED as u8)]);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.peer_subscriber_id(), None);
    assert_eq!(
        decode_batch(&close),
        Ok(Message::Close {
            reason: p::CLOSE_EXPIRED as u8,
            session: true
        })
    );
    let (_, events) = expect_recv(&mut a, &close, 3502);
    assert_eq!(events, [Ev::Closed(p::CLOSE_EXPIRED as u8)]);
    assert_eq!(a.state(), State::Closed);
    assert!(
        b.tick_lease(9999, &mut out)
            .expect("tick")
            .events
            .is_empty()
    );
    println!("[zenoh-exam] session ok lease-expiry-closes");
}

#[test]
fn refuses_router_peer() {
    let mut b = listener();
    let before = snapshot(&b);
    let router = unhex("0109700102030405060708");
    assert_eq!(
        recv(&mut b, &router, 5).err(),
        Some(SessionError::Decode(Refusal::UnsupportedWhatami))
    );
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.state(), State::Idle);
    println!("[zenoh-exam] session refused router-peer");
}

#[test]
fn refuses_version_mismatch() {
    let mut b = listener();
    let before = snapshot(&b);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let length = encode::init_syn(&mut out, &ZID_CONNECTOR, 512).expect("init");
    let mut init = out[..length].to_vec();
    assert_eq!(init[1], 9);
    init[1] = 8;
    assert_eq!(
        recv(&mut b, &init, 5).err(),
        Some(SessionError::Decode(Refusal::UnsupportedVersion))
    );
    assert_eq!(snapshot(&b), before);
    println!("[zenoh-exam] session refused version-mismatch");
}

#[test]
fn refuses_wildcard_key_declaration() {
    let (mut a, mut b) = handshake();
    let before = snapshot(&b);
    let before_sender = snapshot(&a);
    let mut out = [0u8; MAX_BATCH_BYTES];

    assert_eq!(
        a.send_declare_subscriber(1, "demo/**", &mut out).err(),
        Some(SessionError::Encode(EncodeError::WildcardKey))
    );
    assert_eq!(snapshot(&a), before_sender);

    let mut frame = FrameEncoder::new(&mut out, b.expected_rx_sn()).expect("frame");
    frame
        .declare_subscriber(1, Mapping::Receiver, "demo/aa")
        .expect("declare");
    let length = frame.finish().expect("finish");
    let mut wire = out[..length].to_vec();
    patch(&mut wire, b"aa", b"**");
    assert_eq!(
        recv(&mut b, &wire, 6).err(),
        Some(SessionError::Decode(Refusal::WildcardKeyexpr))
    );
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.subscriber_id(), None);
    println!("[zenoh-exam] session refused wildcard-key-declaration");
}

#[test]
fn refuses_push_to_undeclared_key() {
    let (mut a, mut b) = handshake();
    let before = snapshot(&b);
    let undeclared = put_frame(b.expected_rx_sn(), KEY, 0);
    assert_eq!(
        recv(&mut b, &undeclared, 6).err(),
        Some(SessionError::UndeclaredKey)
    );
    assert_eq!(snapshot(&b), before);

    declare(&mut a, &mut b, 1, 7);
    let before = snapshot(&b);
    assert_eq!(b.subscriber_key(), Some(KEY));
    let other = put_frame(b.expected_rx_sn(), "0/slime_demo/other", 0);
    assert_eq!(
        recv(&mut b, &other, 8).err(),
        Some(SessionError::UndeclaredKey)
    );
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.subscriber_key(), Some(KEY));
    println!("[zenoh-exam] session refused push-to-undeclared-key");
}

#[test]
fn refuses_replayed_sequence() {
    let (mut a, mut b) = handshake();
    declare(&mut a, &mut b, 1, 6);
    let sn = b.expected_rx_sn();
    let put = put_frame(sn, KEY, 0);
    let (_, events) = expect_recv(&mut b, &put, 7);
    assert_eq!(events.len(), 1);

    let before = snapshot(&b);
    assert_eq!(
        recv(&mut b, &put, 8).err(),
        Some(SessionError::SequenceMismatch)
    );
    assert_eq!(snapshot(&b), before);
    let skipped = put_frame(sn.wrapping_add(5), KEY, 1);
    assert_eq!(
        recv(&mut b, &skipped, 9).err(),
        Some(SessionError::SequenceMismatch)
    );
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.expected_rx_sn(), sn.wrapping_add(1));
    println!("[zenoh-exam] session refused replayed-sequence");
}

#[test]
fn refuses_frame_before_open() {
    let mut b = listener();
    let early = put_frame(CONNECTOR_SN, KEY, 0);
    let before = snapshot(&b);
    assert_eq!(
        recv(&mut b, &early, 1).err(),
        Some(SessionError::UnexpectedMessage)
    );
    assert_eq!(snapshot(&b), before);

    let mut a = connector();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = a.connect(0, &mut out).expect("connect");
    let (init_syn, _) = owned(&outcome, &out);
    expect_recv(&mut b, &init_syn, 2);
    assert_eq!(b.state(), State::AwaitOpenSyn);
    let before = snapshot(&b);
    assert_eq!(
        recv(&mut b, &early, 3).err(),
        Some(SessionError::UnexpectedMessage)
    );
    assert_eq!(snapshot(&b), before);
    assert!(!b.is_open());
    assert_eq!(b.subscriber_id(), None);
    println!("[zenoh-exam] session refused frame-before-open");
}

#[test]
fn refuses_cookie_mismatch() {
    let mut a = connector();
    let mut b = listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = a.connect(0, &mut out).expect("connect");
    let (init_syn, _) = owned(&outcome, &out);
    expect_recv(&mut b, &init_syn, 1);
    let before = snapshot(&b);

    let mut wrong = cookie();
    wrong[31] ^= 1;
    let length = encode::open_syn(&mut out, LEASE_MS, CONNECTOR_SN, &wrong).expect("open");
    let forged = out[..length].to_vec();
    assert_eq!(
        recv(&mut b, &forged, 2).err(),
        Some(SessionError::CookieMismatch)
    );
    assert_eq!(snapshot(&b), before);

    let length = encode::open_syn(&mut out, LEASE_MS, CONNECTOR_SN, &cookie()[..16]).expect("open");
    let short = out[..length].to_vec();
    assert_eq!(
        recv(&mut b, &short, 3).err(),
        Some(SessionError::CookieMismatch)
    );
    assert_eq!(snapshot(&b), before);
    assert_eq!(b.state(), State::AwaitOpenSyn);
    println!("[zenoh-exam] session refused cookie-mismatch");
}

#[test]
fn frames_the_session_sends_use_the_sender_key_mapping() {
    let (mut a, mut b) = handshake();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = b
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("declare");
    let (declare, _) = owned(&outcome, &out);
    expect_recv(&mut a, &declare, 20);
    let attachment = encode::attachment(1, 2, &gid()).expect("attachment");
    let outcome = a
        .send_put(KEY, &attachment, &[1, 2, 3], &mut out)
        .expect("put");
    let (put, _) = owned(&outcome, &out);
    let outcome = b
        .send_undeclare_subscriber(1, KEY, &mut out)
        .expect("undeclare");
    let (undeclare, _) = owned(&outcome, &out);
    for (name, batch) in [("declare", declare), ("put", put), ("undeclare", undeclare)] {
        let Ok(Message::Frame(frame)) = decode_batch(&batch) else {
            panic!("{name} is not a frame");
        };
        for network in frame.messages() {
            let mapping = match network {
                Network::DeclareSubscriber { mapping, .. }
                | Network::UndeclareSubscriber { mapping, .. }
                | Network::PushPut { mapping, .. } => mapping,
                other => panic!("{name} carried {other:?}, which this side never sends"),
            };
            assert_eq!(mapping, Mapping::Sender, "{name} used the receiver mapping");
        }
    }
}

/// The lease is renewed by anything received, a KEEP_ALIVE included. A session that stays silent
/// past the peer's lease is closed by the lease check, and a received batch inside the lease moves
/// the deadline. The lease check alone is used here: a full `tick` would keep the session alive by
/// sending, which is the point of a keep-alive and is asserted elsewhere.
#[test]
fn a_quiet_link_closes_at_the_lease_and_traffic_renews_it() {
    let (mut a, mut b) = handshake();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let deadline = b.lease_deadline().expect("open session has a deadline");
    // Silence up to the deadline keeps the session open.
    assert!(
        b.tick_lease(deadline, &mut out)
            .expect("tick")
            .events
            .is_empty()
    );
    assert!(b.is_open());
    // Traffic inside the lease moves the deadline by the peer's lease.
    let mut sent = [0u8; MAX_BATCH_BYTES];
    let outcome = a
        .send_declare_subscriber(1, KEY, &mut sent)
        .expect("declare");
    let (frame, _) = owned(&outcome, &sent);
    expect_recv(&mut b, &frame, deadline - 1);
    assert_eq!(b.lease_deadline(), Some(deadline - 1 + LEASE_MS));
    // Silence past the renewed deadline closes it, with the expiry reason.
    let closed = b
        .tick_lease(deadline + LEASE_MS, &mut out)
        .expect("tick past the renewed deadline");
    assert_eq!(b.state(), State::Closed);
    assert_eq!(closed.events.len(), 1);
    assert_eq!(
        decode_batch(closed.batch(&out)),
        Ok(Message::Close {
            reason: p::CLOSE_EXPIRED as u8,
            session: true
        })
    );
    // A KEEP_ALIVE is what renews a link with nothing else to say.
    assert_eq!(decode_batch(&[0x04]), Ok(Message::KeepAlive));
}

/// A session whose own lease is under four milliseconds must not make the cadence zero: after a
/// KEEP_ALIVE the next one is due a millisecond later, not in the same instant.
#[test]
fn a_tiny_own_lease_still_spaces_keep_alives() {
    let (mut a, _b) = handshake_with_leases(3, LEASE_MS);
    let mut out = [0u8; MAX_BATCH_BYTES];
    assert_eq!(a.peer_lease_ms(), LEASE_MS);
    let first = a.tick(5, &mut out).expect("tick");
    assert_eq!(decode_batch(first.batch(&out)), Ok(Message::KeepAlive));
    assert!(
        a.keep_alive_due() > 5,
        "due {} after a send at 5",
        a.keep_alive_due()
    );
    let second = a.tick(5, &mut out).expect("tick");
    assert!(
        second.batch(&out).is_empty(),
        "a second KEEP_ALIVE in the same millisecond"
    );
    let third = a.tick(6, &mut out).expect("tick");
    assert_eq!(decode_batch(third.batch(&out)), Ok(Message::KeepAlive));
}

/// The peer expires a link on the lease announced to it, so the cadence follows the lease this
/// side announced, whatever the peer announced. A stock peer announces 10 s by default and was
/// observed closing a link that had heard nothing for the 2 s lease announced to it.
#[test]
fn keep_alives_follow_the_lease_this_side_announced() {
    let (mut a, b) = handshake_with_leases(2_000, 10_000);
    assert_eq!(a.peer_lease_ms(), 10_000);
    assert_eq!(b.peer_lease_ms(), 2_000);
    let mut out = [0u8; MAX_BATCH_BYTES];
    // `a` last sent at 2, with its OPEN_SYN: due a quarter of its own 2000 ms after that, not of
    // the peer's 10000 ms.
    assert_eq!(a.keep_alive_due(), 2 + 500);
    assert_eq!(a.tick(2 + 499, &mut out).expect("tick").sent, 0);
    let due = a.tick(2 + 500, &mut out).expect("tick");
    assert_eq!(decode_batch(due.batch(&out)), Ok(Message::KeepAlive));
    assert_eq!(a.keep_alive_due(), 2 + 500 + 500);
    // The silence it tolerates from the peer is still the peer's lease.
    let heard = a.lease_deadline().expect("open");
    assert_eq!(heard, 4 + 10_000);
    // `b` announced 10 s, so a quarter of that is its cadence, from its OPEN_ACK at 3. It would
    // expire the link on 2 s of silence from `a`, so only the due time is read here.
    assert_eq!(b.keep_alive_due(), 3 + 2_500);
    assert_eq!(b.lease_deadline(), Some(3 + 2_000));
}

/// A connector announcing `connector_ms` and a listener announcing `listener_ms`, open.
fn handshake_with_leases(connector_ms: u64, listener_ms: u64) -> (Session, Session) {
    let cookie = cookie();
    let mut a = Session::new(
        Role::Connector,
        &Config {
            zid: &ZID_CONNECTOR,
            lease_ms: connector_ms,
            initial_sn: CONNECTOR_SN,
            cookie: &[],
        },
    )
    .expect("connector");
    let mut b = Session::new(
        Role::Listener,
        &Config {
            zid: &ZID_LISTENER,
            lease_ms: listener_ms,
            initial_sn: LISTENER_SN,
            cookie: &cookie,
        },
    )
    .expect("listener");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = a.connect(0, &mut out).expect("connect");
    let (init_syn, _) = owned(&outcome, &out);
    let (init_ack, _) = expect_recv(&mut b, &init_syn, 1);
    let (open_syn, _) = expect_recv(&mut a, &init_ack, 2);
    let (open_ack, _) = expect_recv(&mut b, &open_syn, 3);
    expect_recv(&mut a, &open_ack, 4);
    assert!(a.is_open() && b.is_open());
    (a, b)
}

/// A tick refused for want of output storage leaves the session as it was, the clock included: a
/// later send must not be stamped from a call that did not succeed.
#[test]
fn a_refused_tick_does_not_advance_the_clock() {
    let (mut a, _b) = handshake_with_leases(2_000, 2_000);
    let before = a.now_ms;
    let due = a.keep_alive_due();
    assert!(a.tick(due, &mut []).is_err(), "no room for the KEEP_ALIVE");
    assert_eq!(a.now_ms, before, "keep-alive refused");
    assert_eq!(a.keep_alive_due(), due);
    let expired = a.lease_deadline().expect("open") + 1;
    assert!(a.tick(expired, &mut []).is_err(), "no room for the CLOSE");
    assert_eq!(a.now_ms, before, "expiry refused");
    assert!(a.tick_lease(expired, &mut []).is_err());
    assert_eq!(a.now_ms, before, "expiry refused through tick_lease");
    assert!(a.is_open());
}
