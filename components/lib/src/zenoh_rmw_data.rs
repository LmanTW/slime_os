//! The rmw data exam: a graph session that holds one subscription of its own, against the two data
//! sessions an rmw_zenoh_cpp 0.6.10 peer exchanged with a Slime-side peer.
//!
//! The captured bytes are `fixtures.rs`, generated from `contracts/zenoh-rmw-data/v1` and checked against
//! `scripts/lib/zenoh_rmw_data_exam.py` by `just zenoh_rmw_data_check`. This module replays them into a graph
//! listener and prints one `[zenoh-exam] data ...` line per case. The checker builds the same transcript from
//! the captured bytes and `zenoh_wire`, and owns what each line must be, in what order, and which class each
//! refusal is.

pub(crate) mod fixtures;

use crate::zenoh_profile0::encode::{self, FrameEncoder};
use crate::zenoh_profile0::graph::{
    GRAPH_KEY_BYTES, GRAPH_SLOTS, GraphError, GraphSession, GraphSessionOf, INTEREST_MODE,
    INTEREST_OPTIONS, Kind,
};
use crate::zenoh_profile0::session::{Config, Params, Role};
use crate::zenoh_profile0::{Bounds, Mapping};
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const OTHER_KEY: &str = "0/other/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const SUBSCRIPTION_ID: u32 = 1;
/// The id the rmw_zenoh listener gave its subscriber on the chatter key.
const PEER_SUBSCRIBER_ID: u32 = 23;
const SENT: usize = 8;
/// The payload bound of the session that refuses a 23-byte CDR string: `Hello Slime 0` is 22 bytes.
const PAYLOAD_BOUND: usize = 22;
const COOKIE: &[u8] = b"slime-rmw-capture-cookie-01";
const ZID: [u8; 16] = [
    0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
/// The frames of a captured session, in the order a peer sent them, are `FRAME` batches from the third on.
const HANDSHAKE_BATCHES: usize = 2;
const INTEREST_KEY: &str = "@ros2_lv/0/**";

fn config() -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: 30_000,
        initial_sn: 7,
        cookie: COOKIE,
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| std::format!("{byte:02x}"))
        .collect()
}

fn cdr_string(text: &str) -> Vec<u8> {
    let mut out = std::vec![0x00, 0x01, 0x00, 0x00];
    out.extend_from_slice(&(text.len() as u32 + 1).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}

fn read_string(payload: &[u8]) -> String {
    assert_eq!(
        payload.get(..4),
        Some(&[0x00, 0x01, 0x00, 0x00][..]),
        "a CDR header"
    );
    let length = u32::from_le_bytes(payload[4..8].try_into().expect("a length")) as usize;
    assert_eq!(payload.len(), 8 + length, "a CDR string of its own length");
    assert_eq!(payload.last(), Some(&0), "a NUL-ended CDR string");
    String::from_utf8(payload[8..payload.len() - 1].to_vec()).expect("UTF-8 text")
}

fn leb(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn listener() -> GraphSession {
    GraphSession::new(Role::Listener, &config(), Params::GRAPH).expect("a graph listener")
}

/// A listener with the handshake done, from the first two batches of the listener capture.
fn opened(params: Params) -> GraphSessionOf<GRAPH_SLOTS, GRAPH_SLOTS, GRAPH_KEY_BYTES> {
    let mut session = GraphSessionOf::new(Role::Listener, &config(), params).expect("a listener");
    let mut out = [0u8; 512];
    for (at, (name, hexed)) in fixtures::SLIMEPUB
        .iter()
        .take(HANDSHAKE_BATCHES)
        .enumerate()
    {
        session
            .on_batch(&unhex(hexed), 1 + at as u64, &mut out)
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()));
    }
    assert!(session.is_open(), "the handshake leaves the session open");
    session
}

/// A FRAME of a peer: the session's next expected sequence number and the bytes after it.
fn peer_frame(session: &GraphSession, body: &[u8]) -> Vec<u8> {
    let mut out = std::vec![0x25];
    leb(&mut out, session.expected_rx_sn());
    out.extend_from_slice(body);
    out
}

fn peer_subscribes(session: &mut GraphSession, key: &str) {
    let mut storage = [0u8; 512];
    let mut frame = FrameEncoder::with_bounds(
        &mut storage,
        session.expected_rx_sn(),
        Bounds {
            batch: 400,
            key: GRAPH_KEY_BYTES,
            payload: 512,
        },
    )
    .expect("a frame");
    frame
        .declare_subscriber(PEER_SUBSCRIBER_ID, Mapping::Sender, key)
        .expect("a subscriber declaration");
    let length = frame.finish().expect("a frame");
    let batch = storage[..length].to_vec();
    session
        .on_batch(&batch, 3, &mut [0u8; 512])
        .expect("the peer's subscriber is taken");
}

/// An INTEREST in the capture's layout but for the parts a case changes: the mode, the options and the key.
fn interest_frame(session: &GraphSession, mode: u8, options: u8, key: &str) -> Vec<u8> {
    let mut body = std::vec![0x19 | (mode << 5)];
    leb(&mut body, 3);
    body.push(options);
    leb(&mut body, 0);
    leb(&mut body, key.len() as u32);
    body.extend_from_slice(key.as_bytes());
    peer_frame(session, &body)
}

fn attachment(number: usize) -> [u8; 33] {
    encode::attachment(number as i64 + 1, 1_000_000_000 + number as i64, &GID)
        .expect("an attachment")
}

#[derive(Default)]
struct Run {
    names: Vec<&'static str>,
    delivered: Vec<(u32, i64, i64, String)>,
    dropped: u32,
    delivered_count: u32,
    /// The FRAMEs the session wrote while it replayed the peer's batches.
    replay_wrote: Vec<Vec<u8>>,
    /// The FRAMEs it wrote because the exam asked it to.
    wrote: Vec<Vec<u8>>,
    interest: Option<(u32, String)>,
}

fn note_frame(run: &mut Run, out: &[u8], sent: usize) {
    if sent != 0 && out[0] & 0x1F == 5 {
        run.replay_wrote.push(out[..sent].to_vec());
    }
}

fn finish(run: &mut Run, session: &GraphSession) {
    let counts = session.counts();
    run.dropped = counts.push - counts.delivered;
    run.delivered_count = counts.delivered;
    run.interest = session
        .interest()
        .map(|(id, key)| (id, String::from_utf8(key.to_vec()).expect("a key")));
}

/// A talker published to a Slime subscriber: the session declares its subscription as the first message
/// after the handshake, then takes the peer's batches.
fn peer_publishes() -> Run {
    let mut session = listener();
    let mut run = Run::default();
    let mut out = [0u8; 512];
    for (at, (name, hexed)) in fixtures::PEERPUB.iter().enumerate() {
        let outcome = session
            .on_batch_samples(
                &unhex(hexed),
                1 + at as u64,
                &mut out,
                &mut |_| {},
                &mut |sample| {
                    run.delivered.push((
                        sample.subscription,
                        sample.sequence,
                        sample.timestamp,
                        read_string(sample.payload),
                    ));
                },
            )
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()));
        note_frame(&mut run, &out, outcome.sent);
        run.names.push(name);
        if at + 1 == HANDSHAKE_BATCHES {
            let declared = session
                .send_declare_subscriber(SUBSCRIPTION_ID, KEY, &mut out)
                .expect("the subscription is declared");
            run.wrote.push(out[..declared.sent].to_vec());
        }
    }
    finish(&mut run, &session);
    run
}

/// A listener subscribed to `chatter`: once it declares its subscriber, the session writes a Put on that key
/// for each of the exam's strings.
fn slime_publishes() -> Run {
    let mut session = listener();
    let mut run = Run::default();
    let mut out = [0u8; 512];
    let mut sent = false;
    for (at, (name, hexed)) in fixtures::SLIMEPUB.iter().enumerate() {
        let mut ready = false;
        let outcome = session
            .on_batch_samples(
                &unhex(hexed),
                1 + at as u64,
                &mut out,
                &mut |change| {
                    ready |= change.kind == Kind::Subscriber
                        && change.declared
                        && change.id == PEER_SUBSCRIBER_ID
                        && change.key == KEY.as_bytes();
                },
                &mut |sample| {
                    run.delivered.push((
                        sample.subscription,
                        sample.sequence,
                        sample.timestamp,
                        read_string(sample.payload),
                    ));
                },
            )
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()));
        note_frame(&mut run, &out, outcome.sent);
        run.names.push(name);
        if ready && !sent {
            sent = true;
            for number in 0..SENT {
                let payload = cdr_string(&std::format!("Hello Slime {number}"));
                let written = session
                    .send_put(KEY, &attachment(number), &payload, &mut out)
                    .unwrap_or_else(|error| panic!("put {number}: refused as {}", error.class()));
                run.wrote.push(out[..written.sent].to_vec());
            }
        }
    }
    assert!(
        sent,
        "the listener declared a subscriber on the chatter key"
    );
    finish(&mut run, &session);
    run
}

fn class<T>(result: Result<T, GraphError>) -> &'static str {
    match result {
        Ok(_) => panic!("the session took what the exam says it refuses"),
        Err(error) => error.class(),
    }
}

fn refusals() -> Vec<(&'static str, &'static str)> {
    let mut out = [0u8; 512];
    let mut found = Vec::new();

    let mut session = opened(Params::GRAPH);
    session
        .send_declare_subscriber(SUBSCRIPTION_ID, KEY, &mut out)
        .expect("a first subscription");
    found.push((
        "put-with-a-second-subscription",
        class(session.send_declare_subscriber(2, OTHER_KEY, &mut out)),
    ));

    let mut session = opened(Params::GRAPH);
    let payload = cdr_string("Hello Slime 0");
    found.push((
        "send-before-the-peer-declares",
        class(session.send_put(KEY, &attachment(0), &payload, &mut out)),
    ));

    let mut session = opened(Params::GRAPH);
    peer_subscribes(&mut session, KEY);
    found.push((
        "send-to-another-key",
        class(session.send_put(OTHER_KEY, &attachment(0), &payload, &mut out)),
    ));

    let mut bounded = Params::GRAPH;
    bounded.bounds.payload = PAYLOAD_BOUND;
    let mut session = opened(bounded);
    peer_subscribes(&mut session, KEY);
    assert_eq!(
        payload.len(),
        PAYLOAD_BOUND,
        "the longest string the bound takes"
    );
    session
        .send_put(KEY, &attachment(0), &payload, &mut out)
        .expect("a string of the bound is sent");
    found.push((
        "send-over-the-payload-bound",
        class(session.send_put(KEY, &attachment(1), &cdr_string("Hello Slime 00"), &mut out)),
    ));

    for (name, mode, options, key) in [
        (
            "interest-with-a-second-key",
            INTEREST_MODE,
            INTEREST_OPTIONS,
            "0/chatter/**",
        ),
        (
            "interest-for-subscribers",
            INTEREST_MODE,
            INTEREST_OPTIONS | 0x02,
            INTEREST_KEY,
        ),
        ("interest-future-mode", 2, INTEREST_OPTIONS, INTEREST_KEY),
    ] {
        let mut session = opened(Params::GRAPH);
        let batch = interest_frame(&session, mode, options, key);
        found.push((name, class(session.on_batch(&batch, 3, &mut out))));
    }

    // The one INTEREST the session takes is taken by it, in a frame of the same layout.
    let mut session = opened(Params::GRAPH);
    let batch = interest_frame(&session, INTEREST_MODE, INTEREST_OPTIONS, INTEREST_KEY);
    let outcome = session
        .on_batch(&batch, 3, &mut out)
        .expect("the interest is answered");
    assert_ne!(outcome.sent, 0, "the answer is one frame");
    found
}

#[test]
fn the_data_exam() {
    if let Some(path) = std::env::var_os("ZENOH_RMW_DATA_FIXTURES") {
        let record = std::fs::read_to_string(&path).expect("the hand-off record is readable");
        let mut wanted = String::from("{\n");
        wanted.push_str(&std::format!(
            "  formatVersion = {};\n",
            fixtures::FORMAT_VERSION
        ));
        for (group, rows) in [
            ("peerpub", &fixtures::PEERPUB[..]),
            ("slimepub", &fixtures::SLIMEPUB[..]),
        ] {
            wanted.push_str(&std::format!("  {group} = [\n"));
            for (name, bytes) in rows {
                wanted.push_str(&std::format!(
                    "    {{ name = \"{name}\"; bytes = \"{bytes}\"; }};\n"
                ));
            }
            wanted.push_str("  ];\n");
        }
        wanted.push_str("}\n");
        assert_eq!(
            record, wanted,
            "fixtures.rs differs from the record the exam handed over; run `just zenoh_rmw_data_gen`"
        );
    }
    assert_eq!(fixtures::FORMAT_VERSION, 1);

    let peerpub = peer_publishes();
    let slimepub = slime_publishes();
    let refused = refusals();
    let line = |text: &str| std::println!("[zenoh-exam] data {text}");

    for name in peerpub.names.iter().chain(slimepub.names.iter()) {
        line(&std::format!("replay {name} ok"));
    }
    assert_eq!(peerpub.delivered_count as usize, peerpub.delivered.len());
    for (subscription, sequence, timestamp, text) in &peerpub.delivered {
        line(&std::format!(
            "delivered {subscription} {sequence} {timestamp} {}",
            text.replace(' ', "_")
        ));
    }
    line(&std::format!("dropped peerpub {}", peerpub.dropped));
    line(&std::format!(
        "delivered-none slimepub {}",
        slimepub.delivered.len()
    ));
    line(&std::format!("dropped slimepub {}", slimepub.dropped));
    for (label, run) in [("peerpub", &peerpub), ("slimepub", &slimepub)] {
        assert_eq!(
            run.replay_wrote.len(),
            1,
            "{label}: one frame was written for the INTEREST"
        );
        line(&std::format!(
            "replay-wrote {label} {}",
            hex(&run.replay_wrote[0])
        ));
    }
    let (id, key) = peerpub
        .interest
        .as_ref()
        .expect("the talker session answered an INTEREST");
    assert_eq!(
        slimepub.interest.as_ref(),
        Some(&(*id, key.clone())),
        "both sessions name one INTEREST"
    );
    line(&std::format!(
        "interest {id} {INTEREST_MODE} {INTEREST_OPTIONS:#04x} {key}"
    ));
    assert_eq!(peerpub.wrote.len(), 1);
    line(&std::format!("wrote subscriber {}", hex(&peerpub.wrote[0])));
    assert_eq!(slimepub.wrote.len(), SENT);
    for (number, frame) in slimepub.wrote.iter().enumerate() {
        line(&std::format!("wrote put-{number} {}", hex(frame)));
    }
    line("ok peer-publishes-to-a-slime-subscriber");
    line("ok slime-publishes-to-a-peer-subscriber");
    for (name, class) in refused {
        line(&std::format!("refused {name} {class}"));
    }
}

/// The answer to an INTEREST is traffic: it restarts the keep-alive cadence from the time of the batch that
/// asked for it, not from the earlier batch the session last saw.
#[test]
fn the_answer_to_an_interest_restarts_the_keep_alive() {
    let mut out = [0u8; 512];
    let mut session = opened(Params::GRAPH);
    let batch = interest_frame(&session, INTEREST_MODE, INTEREST_OPTIONS, INTEREST_KEY);
    let answered = session
        .on_batch(&batch, 7_000, &mut out)
        .expect("the interest is answered");
    assert_ne!(answered.sent, 0, "the answer is one frame");
    let quiet = session.tick(7_600, &mut out).expect("a tick");
    assert_eq!(
        quiet.sent, 0,
        "600 ms after the answer is before a quarter lease"
    );
    let due = session.tick(14_500, &mut out).expect("a tick");
    assert_ne!(
        due.sent, 0,
        "a quarter lease after the answer is a keep-alive"
    );
}
