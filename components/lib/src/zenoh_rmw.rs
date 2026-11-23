//! The rmw exam: Profile 0 against the three sessions an rmw_zenoh_cpp 0.6.10 peer sent.
//!
//! The captured bytes are `fixtures.rs`, generated from `contracts/zenoh-rmw-session/v1` and checked
//! against `scripts/lib/zenoh_rmw_exam.py` by `just zenoh_rmw_check`. This module replays them into a
//! graph listener and prints one `[zenoh-exam] rmw ...` line per case; the checker owns what those lines
//! must be, in what order, and which class each refusal is.

pub(crate) mod fixtures;

use crate::zenoh_profile0::graph::{
    Counts, GRAPH_BATCH_BYTES, GRAPH_KEY_BYTES, GraphSession, decode_graph_batch,
};
use crate::zenoh_profile0::session::{Config, Params, Role, SessionError, State};
use crate::zenoh_profile0::{MAX_BATCH_BYTES, STREAM_LENGTH_BYTES, StreamFramerOf};
use std::string::String;
use std::vec::Vec;

const GROUPS: [(&str, &[(&str, &str)]); 3] = [
    ("talker", &fixtures::TALKER),
    ("listener", &fixtures::LISTENER),
    ("lists", &fixtures::LISTS),
];
/// The cookie our listener offers; the peer echoes it in its OPEN_SYN.
const COOKIE: &[u8] = b"slime-rmw-capture-cookie-01";
const ZID: [u8; 16] = [
    0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
];

fn line(text: &str) {
    println!("[zenoh-exam] rmw {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn config() -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: 30_000,
        initial_sn: 7,
        cookie: COOKIE,
    }
}

fn listener() -> GraphSession {
    GraphSession::new(Role::Listener, &config(), Params::GRAPH).expect("a graph listener")
}

fn named(rows: &[(&str, &str)], name: &str) -> Vec<u8> {
    unhex(
        rows.iter()
            .find(|(candidate, _)| *candidate == name)
            .unwrap_or_else(|| panic!("the peer sent no batch named {name}"))
            .1,
    )
}

/// Replays one group, and returns the INIT_ACK, the counts and how many bytes the listener sent after
/// its OPEN_ACK. The replay prints one line for each batch.
fn replay(rows: &[(&str, &str)]) -> (Vec<u8>, Counts, usize) {
    let mut ours = listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut init_ack = Vec::new();
    let mut after = 0usize;
    for (at, (name, hexed)) in rows.iter().enumerate() {
        let batch = unhex(hexed);
        let outcome = ours
            .on_batch(&batch, 1 + at as u64, &mut out)
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()));
        match at {
            0 => init_ack = outcome.batch(&out).to_vec(),
            1 => assert_eq!(outcome.sent, 3, "{name}: an OPEN_ACK is three bytes"),
            _ => after += outcome.sent,
        }
        line(&format!("replay {name} ok"));
    }
    (init_ack, *ours.counts(), after)
}

/// The decoder's properties on each captured batch: no proper prefix is accepted unless it is a shorter
/// frame, a flipped bit never panics or exceeds a bound, and every two-chunk split of the framed batch
/// reassembles to it.
fn properties(name: &str, batch: &[u8]) {
    let bounds = Params::GRAPH.bounds;
    let whole = match decode_graph_batch(batch, &bounds) {
        Ok(crate::zenoh_profile0::graph::GraphMessage::Frame(frame)) => {
            Some(frame.messages().count())
        }
        Ok(_) => None,
        Err(refusal) => panic!("{name} is not accepted: {refusal:?}"),
    };
    for length in 0..batch.len() {
        match decode_graph_batch(&batch[..length], &bounds) {
            Err(_) => {}
            Ok(crate::zenoh_profile0::graph::GraphMessage::Frame(frame)) => {
                let total = whole.unwrap_or_else(|| {
                    panic!("{name}: a non-frame decoded a {length}-byte prefix")
                });
                assert!(
                    frame.messages().count() < total,
                    "{name}: a {length}-byte prefix decoded as much as the whole"
                );
            }
            Ok(_) => {}
        }
    }
    for position in 0..batch.len() {
        for flip in [0x01u8, 0x80] {
            let mut mutated = batch.to_vec();
            mutated[position] ^= flip;
            if let Ok(crate::zenoh_profile0::graph::GraphMessage::Frame(frame)) =
                decode_graph_batch(&mutated, &bounds)
            {
                assert!(frame.messages().count() <= GRAPH_BATCH_BYTES);
            }
        }
    }
    let mut framed = (batch.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(batch);
    for cut in 1..framed.len() {
        let mut framer = StreamFramerOf::<{ STREAM_LENGTH_BYTES + GRAPH_BATCH_BYTES }>::new();
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

/// A frame the listener refuses, and the class. `graph` selects the graph listener or the plain one.
fn refuse(name: &str, batch: &[u8], graph: bool) -> &'static str {
    if !graph {
        // The plain session, opened by the talker's own INIT_SYN and OPEN_SYN. The plain decoder refuses
        // the talker's INIT extensions, so the handshake is the plain one a stock peer sends: our INIT_SYN
        // shape with the same cookie and the first sequence number the exam's frames carry.
        let talker = GROUPS[0].1;
        let mut plain = crate::zenoh_profile0::session::Session::new(Role::Listener, &config())
            .expect("plain listener");
        let mut out = [0u8; MAX_BATCH_BYTES];
        plain
            .on_batch(&plain_init_syn(), 1, &mut out)
            .expect("INIT_SYN");
        let sn = open_syn_sn(&named(talker, "talker-02-open-syn"));
        let length = crate::zenoh_profile0::encode::open_syn(&mut out, 30_000, sn, COOKIE)
            .expect("OPEN_SYN");
        let open = out[..length].to_vec();
        plain.on_batch(&open, 2, &mut out).expect("OPEN_SYN");
        assert_eq!(plain.state(), State::Open);
        return match plain.on_batch(batch, 3, &mut out) {
            Ok(_) => panic!("{name}: the default session accepted it"),
            Err(SessionError::Decode(refusal)) => refusal.name(),
            Err(SessionError::UndeclaredKey) => "undeclared-key",
            Err(other) => panic!("{name}: refused as a class the exam does not name: {other:?}"),
        };
    }
    refuse_graph(name, batch)
}

/// The initial sequence number an OPEN_SYN announces: its header, the lease, then the number.
fn open_syn_sn(batch: &[u8]) -> u32 {
    let mut at = 1;
    let mut numbers = [0u32; 2];
    for number in &mut numbers {
        let mut value = 0u32;
        let mut shift = 0;
        loop {
            let byte = batch[at];
            at += 1;
            value |= u32::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        *number = value;
    }
    numbers[1]
}

fn plain_init_syn() -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let length =
        crate::zenoh_profile0::encode::init_syn(&mut out, &[0xa1; 8], 512).expect("INIT_SYN");
    out[..length].to_vec()
}

fn refuse_graph(name: &str, batch: &[u8]) -> &'static str {
    let talker = GROUPS[0].1;
    let mut ours = listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    // An INIT_SYN is judged by the handshake; every other variant goes to an open session.
    if batch.first().is_some_and(|header| header & 0x1F == 1) {
        return match ours.on_batch(batch, 1, &mut out) {
            Ok(_) => panic!("{name}: the graph listener accepted it"),
            Err(error) => error.class(),
        };
    }
    ours.on_batch(&named(talker, "talker-01-init-syn"), 1, &mut out)
        .expect("INIT_SYN");
    ours.on_batch(&named(talker, "talker-02-open-syn"), 2, &mut out)
        .expect("OPEN_SYN");
    match ours.on_batch(batch, 3, &mut out) {
        Ok(_) => panic!("{name}: the graph listener accepted it"),
        Err(error) => error.class(),
    }
}

/// Every refusal the exam pins, with the batch the host reference built.
fn refusals() {
    for (name, hexed) in fixtures::REFUSE {
        let batch = unhex(hexed);
        let class = refuse(name, &batch, !name.contains("-default-"));
        line(&format!("refused {name} {class}"));
    }
}

/// A key of 253 bytes, the longest the peer declared, is taken, as one alias in one FRAME.
fn key_of_253_bytes_is_taken() {
    let talker = GROUPS[0].1;
    let mut ours = listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.on_batch(&named(talker, "talker-01-init-syn"), 1, &mut out)
        .expect("INIT_SYN");
    ours.on_batch(&named(talker, "talker-02-open-syn"), 2, &mut out)
        .expect("OPEN_SYN");
    let key = "k".repeat(GRAPH_KEY_BYTES);
    // The talker's first FRAME header and sequence number, then one DECLARE with the network QoS
    // extension that declares alias 1 for the key. The key's length is two LEB128 bytes.
    let first = named(talker, "talker-03-frame");
    let declare_at = first
        .iter()
        .position(|&byte| byte == 0x9e)
        .expect("a DECLARE");
    let mut frame = first[..declare_at].to_vec();
    frame.extend_from_slice(&[0x9e, 0x21, 0x08, 0x20, 0x01, 0x00]);
    frame.extend_from_slice(&[0x80 | (GRAPH_KEY_BYTES as u8 & 0x7f), 0x01]);
    frame.extend_from_slice(key.as_bytes());
    assert!(frame.len() <= GRAPH_BATCH_BYTES);
    let outcome = ours
        .on_batch(&frame, 3, &mut out)
        .unwrap_or_else(|error| panic!("a key of {GRAPH_KEY_BYTES} bytes: {}", error.class()));
    assert_eq!(outcome.counts.keyexpr, 1);
    line("ok graph-key-of-253-bytes-is-taken");
}

/// The three sessions, in the order the exam lists them: the replays, what the listener sent, the
/// scenarios, the counts, the properties and the refusals.
#[test]
fn the_rmw_peer_exam() {
    let mut sent: Vec<(&str, Vec<u8>, usize)> = Vec::new();
    let mut counts: Vec<(&str, Counts)> = Vec::new();
    for (group, rows) in GROUPS {
        let (init_ack, group_counts, after) = replay(rows);
        sent.push((group, init_ack, after));
        counts.push((group, group_counts));
    }
    for (group, init_ack, after) in &sent {
        line(&format!("sent {group} init-ack {}", hex(init_ack)));
        line(&format!("sent {group} after-handshake {after}"));
    }
    line("ok talker-session-opens-and-closes");
    line("ok listener-session-holds-its-subscription");
    line("ok lists-session-withdraws-what-it-declared");
    key_of_253_bytes_is_taken();
    for (group, group_counts) in &counts {
        for (kind, count) in group_counts.each() {
            if count != 0 {
                line(&format!("count {group} {kind} {count}"));
            }
        }
    }
    for (_group, rows) in GROUPS {
        for (name, hexed) in rows {
            let batch = unhex(hexed);
            if batch.first().is_some_and(|header| header & 0x1F == 5) {
                properties(name, &batch);
            } else {
                line(&format!("property {name} ok"));
            }
        }
    }
    refusals();
}

#[test]
fn the_constants_are_the_handed_off_record() {
    assert_eq!(fixtures::FORMAT_VERSION, 1);
    let Some(path) = std::env::var_os("ZENOH_RMW_FIXTURES") else {
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
        ("talker", &fixtures::TALKER[..]),
        ("listener", &fixtures::LISTENER[..]),
        ("lists", &fixtures::LISTS[..]),
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
        "fixtures.rs differs from the record the exam handed over; run `just zenoh_rmw_gen`"
    );
}
