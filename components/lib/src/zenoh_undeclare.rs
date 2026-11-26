//! The undeclare exam: Profile 0 against the session a stock eclipse-zenoh 1.0.0 peer ended with an
//! UndeclareSubscriber that names its subscriber by id alone.
//!
//! The captured bytes are `fixtures.rs`, generated from `contracts/zenoh-stock-undeclare/v1` and
//! checked against `scripts/lib/zenoh_undeclare_exam.py` by `just zenoh_undeclare_check`. This module
//! replays them into a connector session and prints one `[zenoh-exam] undeclare ...` line per case;
//! `scripts/check/check-zenoh-profile0.py --slice undeclare` owns what those lines must be.

mod fixtures;

use crate::zenoh_profile0::encode::{self, FrameEncoder};
use crate::zenoh_profile0::session::{Config, Event, Role, Session, SessionError, State};
use crate::zenoh_profile0::{
    GID_BYTES, MAX_ATTACHMENT_BYTES, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, Mapping,
    Message, Network, StreamFramer, decode_batch,
};
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const UNDECLARE: &str = "undeclares-07-undeclare-subscriber";
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
const SAMPLES: [(i64, &str); 4] = [
    (0, "00010000000000000a000000"),
    (1, "000100000100000014000000"),
    (2, "00010000020000001e000000"),
    (3, "000100000300000028000000"),
];

fn line(text: &str) {
    println!("[zenoh-exam] undeclare {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// A batch the peer sent, by name.
fn captured(name: &str) -> Vec<u8> {
    fixtures::PEER
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, bytes)| unhex(bytes))
        .unwrap_or_else(|| panic!("the peer sent no batch named {name}"))
}

/// The refusal class the exam pins for an error: the decoder's own, or the session's.
fn class_of(error: SessionError) -> &'static str {
    match error {
        SessionError::Decode(refusal) => refusal.name(),
        SessionError::UnknownSubscriber => "unknown-subscriber",
        other => {
            panic!("an undeclaration was refused as a class the exam does not name: {other:?}")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Handshake,
    Declared(u32),
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
            Event::SubscriberUndeclared { id } => Ev::Undeclared(id),
            Event::Closed { reason } => Ev::Closed(reason),
            other => panic!("the exam raised an event it does not name: {other:?}"),
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

fn feed_named(session: &mut Session, name: &str, now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    feed(session, &captured(name), now_ms).unwrap_or_else(|error| panic!("{name}: {error:?}"))
}

fn connector_config() -> Config<'static> {
    Config {
        zid: &[0xa1; 8],
        lease_ms: 10_000,
        initial_sn: 9000,
        cookie: &[],
    }
}

/// A connector that has taken the peer's first five batches and so holds its subscriber, and the time
/// after them.
fn declared_connector() -> (Session, u64) {
    let mut ours = Session::new(Role::Connector, &connector_config()).expect("connector");
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.connect(0, &mut out).expect("connect");
    for (at, (name, _)) in fixtures::PEER[..5].iter().enumerate() {
        feed_named(&mut ours, name, 1 + at as u64);
    }
    assert!(ours.is_open());
    assert_eq!(ours.peer_subscriber_id(), Some(1));
    assert_eq!(ours.peer_subscriber_key(), Some(KEY));
    (ours, 6)
}

/// The peer's whole session, replayed in the order it was sent.
fn stock_undeclares_by_id() {
    let mut ours = Session::new(Role::Connector, &connector_config()).expect("connector");
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.connect(0, &mut out).expect("connect");
    let mut now = 0;
    let mut replay = |ours: &mut Session, name: &str| {
        now += 1;
        let result = feed_named(ours, name, now);
        line(&format!("replay {name} ok"));
        result
    };

    let (open_syn, events) = replay(&mut ours, "undeclares-01-init-ack");
    assert!(events.is_empty());
    assert!(matches!(
        decode_batch(&open_syn),
        Ok(Message::OpenSyn { .. })
    ));
    let (_, events) = replay(&mut ours, "undeclares-02-open-ack");
    assert_eq!(events, [Ev::Handshake]);
    let (_, events) = replay(&mut ours, "undeclares-03-oam");
    assert!(events.is_empty());
    let (_, events) = replay(&mut ours, "undeclares-04-declare-keyexpr");
    assert!(events.is_empty());
    let (_, events) = replay(&mut ours, "undeclares-05-declare-subscriber-declare-final");
    assert_eq!(events, [Ev::Declared(1)]);
    assert_eq!(ours.peer_subscriber_id(), Some(1));

    for (sequence, payload) in SAMPLES {
        let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
        ours.send_put(KEY, &attachment, &unhex(payload), &mut out)
            .expect("put to the declared key");
    }

    let (_, events) = replay(&mut ours, "undeclares-06-keep-alive");
    assert!(events.is_empty());
    assert_eq!(ours.peer_subscriber_id(), Some(1));
    let (sent, events) = replay(&mut ours, UNDECLARE);
    assert!(sent.is_empty());
    assert_eq!(events, [Ev::Undeclared(1)]);
    assert_eq!(ours.peer_subscriber_id(), None);
    assert_eq!(ours.peer_subscriber_key(), None);
    assert!(ours.is_open());
    assert!(matches!(
        ours.send_put(KEY, &[0; 33], &[0; 12], &mut out).err(),
        Some(SessionError::UndeclaredKey)
    ));
    let (_, events) = replay(&mut ours, "undeclares-08-close");
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(ours.state(), State::Closed);
    line("ok stock-undeclares-by-id");
}

/// The undeclaration by id alone leaves a session as the full form does: the same state and the same
/// event, at the same time.
fn bare_and_full_undeclare_agree() {
    let (mut bare, now) = declared_connector();
    let (mut full, _) = declared_connector();
    let sn = full.expected_rx_sn();
    assert_eq!(sn, bare.expected_rx_sn());
    let mut buffer = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut buffer, sn).expect("frame");
    frame
        .undeclare_subscriber(1, Mapping::Sender, KEY)
        .expect("undeclare");
    let length = frame.finish().expect("finish");
    let full_form = buffer[..length].to_vec();
    assert_ne!(full_form, captured(UNDECLARE));

    let by_id = feed_named(&mut bare, UNDECLARE, now);
    let in_full = feed(&mut full, &full_form, now).expect("the full form");
    assert_eq!(by_id, in_full);
    assert_eq!(by_id.1, [Ev::Undeclared(1)]);
    assert_eq!(snapshot(&bare), snapshot(&full));
    assert_eq!(bare.peer_subscriber_id(), None);
    line("ok bare-and-full-undeclare-agree");
}

/// Each variant, through a session that holds the peer's subscriber, which must come out unchanged.
fn refusals() {
    for (name, bytes) in fixtures::REFUSE {
        let (mut ours, now) = declared_connector();
        if name == "refuse-undeclare-repeated" {
            feed_named(&mut ours, UNDECLARE, now);
        }
        let before = snapshot(&ours);
        let error = feed(&mut ours, &unhex(bytes), now + 1).expect_err(name);
        assert_eq!(snapshot(&ours), before, "{name} changed the session");
        line(&format!("refused {name} {}", class_of(error)));
    }
}

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
            | Network::DeclareQueryable { .. }
            | Network::UndeclareQueryable { .. }
            | Network::Request { .. }
            | Network::Response { .. }
            | Network::ResponseFinal { .. }
            | Network::DeclareFinal => {}
        }
    }
}

/// No proper prefix is accepted unless it is a shorter frame, a flipped bit never panics or exceeds a
/// bound, and every two-chunk split of the framed batch reassembles to it.
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
fn the_constants_are_the_handed_off_record() {
    assert_eq!(fixtures::FORMAT_VERSION, 1);
    let Some(path) = std::env::var_os("ZENOH_UNDECLARE_FIXTURES") else {
        return;
    };
    let record = std::fs::read_to_string(&path).expect("the hand-off record is readable");
    let mut wanted = String::new();
    wanted.push_str("{\n");
    wanted.push_str(&format!(
        "  formatVersion = {};\n",
        fixtures::FORMAT_VERSION
    ));
    for (group, rows) in [
        ("peer", &fixtures::PEER[..]),
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
        "fixtures.rs differs from the record the exam handed over; run `just zenoh_undeclare_gen`"
    );
}

/// Every section, in the order the exam lists them.
#[test]
fn the_stock_peer_undeclare_exam() {
    stock_undeclares_by_id();
    bare_and_full_undeclare_agree();
    for (name, bytes) in fixtures::PEER {
        properties(name, &unhex(bytes));
    }
    refusals();
}
