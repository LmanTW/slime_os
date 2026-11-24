//! The lanes exam. Each `[zenoh-exam] lanes ...` line is printed after every scenario has run, and
//! `scripts/lib/zenoh_lanes_exam.py` builds the same transcript from its reference model and requires the lines to
//! be equal. The batches are built here in Rust, from the header bytes `zenoh-codec` 1.0.0 wrote, so a `fed` line
//! carries the length and a digest of the batch the link was given and the judge sees any batch that differs.
//!
//! The link under test is the listener of a heap configuration with a 2048-byte batch, a reassembly timeout of
//! 5000 ms and an initial sequence number of 7000. Its owner holds the one subscription on the demo key.

use super::{Pipe, Scripted};
use crate::zenoh_link::{Error, LinkHandle, LinkOf, Notice};
use crate::zenoh_profile0::encode::{init_ack, init_ack_qos, init_syn, init_syn_qos};
use crate::zenoh_profile0::fragment::tests as codec;
use crate::zenoh_profile0::lane::Lane;
use crate::zenoh_profile0::limits::HEAP;
use crate::zenoh_profile0::session::{Config, DropCause, Params, Role};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::format;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;

const OTHER_KEY: &str = "0/slime_demo/other/Counter";
const DEFAULT_PRIORITY: u8 = 5;
const SN0: u32 = 7000;
const BATCH: usize = 2048;
const TIMEOUT_MS: u64 = 5000;
const BIG: usize = 4200;
const SMALL: usize = 100;
const HALF: u32 = 1 << 31;
const LEASE_MS: u64 = 4_000_000_000;
const ZID: [u8; 3] = [0x11, 0x22, 0x33];
const PEER_ZID: [u8; 3] = [0x44, 0x55, 0x66];
const COOKIE: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

type Exam<const R: usize> = LinkOf<Scripted, 2048, 4, 5, 129, 0, 8, 4, R>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn leb(value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = value;
    loop {
        let byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

// ------------------------------------------------------------------------------------ the host builders

fn qos_ext(priority: u8, mandatory: bool, more: bool) -> Vec<u8> {
    let id = if mandatory { 0x31 } else { 0x21 } | if more { 0x80 } else { 0 };
    let mut out = std::vec![id];
    out.extend(leb(u32::from(priority)));
    out
}

/// What a stock peer writes: nothing for the default priority, the mandatory QoS extension otherwise.
fn lane_ext(priority: u8) -> Vec<u8> {
    if priority == DEFAULT_PRIORITY {
        Vec::new()
    } else {
        qos_ext(priority, true, false)
    }
}

fn frame_header(reliable: bool, priority: u8, sn: u32, ext: Option<Vec<u8>>) -> Vec<u8> {
    let ext = ext.unwrap_or_else(|| lane_ext(priority));
    let mut out =
        std::vec![0x05 | if reliable { 0x20 } else { 0 } | if ext.is_empty() { 0 } else { 0x80 }];
    out.extend(leb(sn));
    out.extend(ext);
    out
}

fn fragment_header(
    reliable: bool,
    priority: u8,
    more: bool,
    sn: u32,
    ext: Option<Vec<u8>>,
) -> Vec<u8> {
    let ext = ext.unwrap_or_else(|| lane_ext(priority));
    let flags = if reliable { 0x20 } else { 0 }
        | if more { 0x40 } else { 0 }
        | if ext.is_empty() { 0 } else { 0x80 };
    let mut out = std::vec![0x06 | flags];
    out.extend(leb(sn));
    out.extend(ext);
    out
}

/// A PUSH with a Put: the sequence number and timestamp attachment, and a payload of the pattern the captures carry.
fn put(seq: i64, size: usize, key: &str) -> Vec<u8> {
    let mut attachment = Vec::new();
    attachment.extend_from_slice(&seq.to_le_bytes());
    attachment.extend_from_slice(&(1000 + seq).to_le_bytes());
    attachment.push(16);
    attachment.extend_from_slice(&codec::GID);
    assert_eq!(attachment.len(), 33);
    let mut out = std::vec![0x1d | 0x20 | 0x40, 0x00];
    out.extend(leb(key.len() as u32));
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&[0x01 | 0x80, 0x43, 33]);
    out.extend(attachment);
    out.extend(leb(size as u32));
    out.extend((0..size).map(|i| ((i * 7 + 1) % 251) as u8));
    out
}

/// One batch the link is given, and the lane and sequence number it was built for.
#[derive(Clone)]
struct Item {
    lane: (u8, bool),
    sn: u32,
    body: Vec<u8>,
}

fn frame_of(sn: u32, priority: u8, reliable: bool, message: &[u8], ext: Option<Vec<u8>>) -> Item {
    let mut body = frame_header(reliable, priority, sn, ext);
    body.extend_from_slice(message);
    Item {
        lane: (priority, reliable),
        sn,
        body,
    }
}

fn fragments_of(message: &[u8], first_sn: u32, priority: u8, reliable: bool) -> Vec<Item> {
    let mut out = Vec::new();
    let (mut at, mut sn) = (0usize, first_sn);
    while at < message.len() {
        let ext = lane_ext(priority);
        let room = BATCH - 2 - (1 + leb(sn).len() + ext.len());
        let end = (at + room).min(message.len());
        let mut body = fragment_header(reliable, priority, end < message.len(), sn, None);
        body.extend_from_slice(&message[at..end]);
        out.push(Item {
            lane: (priority, reliable),
            sn,
            body,
        });
        at = end;
        sn = sn.wrapping_add(1);
    }
    out
}

fn interleave(runs: &[Vec<Item>]) -> Vec<Item> {
    let longest = runs.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::new();
    for index in 0..longest {
        for run in runs {
            if let Some(item) = run.get(index) {
                out.push(item.clone());
            }
        }
    }
    out
}

// ------------------------------------------------------------------------------------- the scenarios

enum Step {
    Batch(Item),
    Tick,
}

struct Scenario {
    name: &'static str,
    runs: usize,
    negotiated: bool,
    events: Vec<(u64, Step)>,
    refused: Option<&'static str>,
}

fn at_time(items: Vec<Item>) -> Vec<(u64, Step)> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| (index as u64, Step::Batch(item)))
        .collect()
}

fn big(seq: i64) -> Vec<u8> {
    put(seq, BIG, codec::KEY)
}

fn small(seq: i64) -> Vec<u8> {
    put(seq, SMALL, codec::KEY)
}

fn frames(items: &[(u32, u8, bool, Vec<u8>)]) -> Vec<(u64, Step)> {
    at_time(
        items
            .iter()
            .map(|(sn, priority, reliable, message)| {
                frame_of(*sn, *priority, *reliable, message, None)
            })
            .collect(),
    )
}

fn good(name: &'static str, events: Vec<(u64, Step)>) -> Scenario {
    Scenario {
        name,
        runs: 2,
        negotiated: true,
        events,
        refused: None,
    }
}

fn refuse(name: &'static str, class: &'static str, events: Vec<(u64, Step)>) -> Scenario {
    Scenario {
        refused: Some(class),
        ..good(name, events)
    }
}

fn single_run(name: &'static str, class: &'static str, events: Vec<(u64, Step)>) -> Scenario {
    Scenario {
        runs: 1,
        negotiated: false,
        ..refuse(name, class, events)
    }
}

fn scenarios() -> Vec<Scenario> {
    let mut out = std::vec![
        good(
            "reliable-lanes-interleaved",
            at_time(interleave(&[
                fragments_of(&big(1), SN0, 2, true),
                fragments_of(&big(2), SN0, 5, true),
            ])),
        ),
        good(
            "reliable-same-sn-on-two-lanes",
            frames(&[
                (SN0, 0, true, small(3)),
                (SN0, 7, true, small(4)),
                (SN0 + 1, 0, true, small(5)),
            ]),
        ),
        good(
            "best-effort-frame-delivered",
            frames(&[(SN0, 5, false, small(6))])
        ),
        good(
            "best-effort-frame-gap",
            frames(&[(SN0, 5, false, small(7)), (SN0 + 3, 5, false, small(8))]),
        ),
        good(
            "best-effort-frame-stale",
            frames(&[
                (SN0, 5, false, small(9)),
                (SN0, 5, false, small(10)),
                (SN0 + 2, 5, false, small(11)),
                (SN0 + 1, 5, false, small(12)),
            ]),
        ),
        good(
            "best-effort-fragments",
            at_time(fragments_of(&big(13), SN0, 3, false)),
        ),
        good("best-effort-fragment-lost-middle", {
            let first = fragments_of(&big(14), SN0, 3, false);
            let mut items = std::vec![first[0].clone(), first[2].clone()];
            items.extend(fragments_of(&big(15), SN0 + 3, 3, false));
            at_time(items)
        }),
        good(
            "best-effort-fragment-lost-first",
            at_time(fragments_of(&big(16), SN0, 3, false)[1..].to_vec()),
        ),
        good("best-effort-lost-final-discards-next", {
            let mut items = fragments_of(&big(17), SN0, 4, false)[..2].to_vec();
            items.extend(fragments_of(&big(18), SN0 + 3, 4, false));
            items.extend(fragments_of(&big(19), SN0 + 6, 4, false));
            at_time(items)
        }),
        good("best-effort-run-timeout", {
            let parts = fragments_of(&big(20), SN0, 4, false);
            std::vec![
                (0, Step::Batch(parts[0].clone())),
                (TIMEOUT_MS, Step::Tick),
                (TIMEOUT_MS + 1, Step::Tick),
                (TIMEOUT_MS + 2, Step::Batch(parts[1].clone())),
                (TIMEOUT_MS + 3, Step::Batch(parts[2].clone())),
                (
                    TIMEOUT_MS + 4,
                    Step::Batch(frame_of(SN0 + 3, 4, false, &small(21), None)),
                ),
            ]
        }),
        good(
            "best-effort-lane-limit",
            at_time(interleave(&[
                fragments_of(&big(22), SN0, 1, false),
                fragments_of(&big(23), SN0, 2, false),
                fragments_of(&big(24), SN0, 3, false),
            ])),
        ),
        good("frame-on-another-lane-during-a-run", {
            let parts = fragments_of(&big(42), SN0, 2, true);
            let mut items = std::vec![parts[0].clone(), frame_of(SN0, 5, true, &small(29), None)];
            items.extend(parts[1..].iter().cloned());
            at_time(items)
        }),
        good("best-effort-frame-after-a-lost-final-fragment", {
            let mut items = fragments_of(&big(37), SN0, 3, false)[..2].to_vec();
            items.push(frame_of(SN0 + 3, 3, false, &small(47), None));
            items.extend(fragments_of(&big(50), SN0 + 4, 3, false));
            at_time(items)
        }),
        good("best-effort-stale-frame-leaves-the-run", {
            let parts = fragments_of(&big(48), SN0 + 1, 3, false);
            let mut items = std::vec![parts[0].clone(), frame_of(SN0, 3, false, &small(49), None)];
            items.extend(parts[1..].iter().cloned());
            at_time(items)
        }),
        good(
            "best-effort-half-window-edge",
            frames(&[
                (SN0, 5, false, small(43)),
                (SN0 + HALF, 5, false, small(44)),
                (SN0 + HALF - 1, 5, false, small(45)),
                (SN0, 5, false, small(46)),
            ]),
        ),
        good(
            "reliable-and-best-effort-on-one-priority",
            at_time(interleave(&[
                fragments_of(&big(25), SN0, 5, true),
                fragments_of(&big(26), SN0, 5, false),
            ])),
        ),
        good(
            "explicit-default-priority",
            at_time(std::vec![
                frame_of(SN0, 5, true, &small(27), Some(qos_ext(5, true, false))),
                frame_of(SN0 + 1, 5, true, &small(28), None),
            ]),
        ),
    ];
    let f_big = |priority: u8, reliable: bool, first: u32| {
        fragments_of(&big(40), first, priority, reliable)
    };
    let one = |item: &Item| std::vec![item.clone()];
    let lone = |item: Item| at_time(std::vec![item]);
    out.push(refuse(
        "priority-8-on-frame",
        "unsupported-extension",
        at_time(std::vec![frame_of(
            SN0,
            0,
            true,
            &small(30),
            Some(qos_ext(8, true, false))
        )]),
    ));
    out.push(refuse("priority-8-on-fragment", "unsupported-extension", {
        let mut body = fragment_header(true, 0, true, SN0, Some(qos_ext(8, true, false)));
        body.push(b'x');
        lone(Item {
            lane: (0, true),
            sn: SN0,
            body,
        })
    }));
    out.push(refuse(
        "qos-extension-not-mandatory",
        "unsupported-extension",
        lone(frame_of(
            SN0,
            2,
            true,
            &small(31),
            Some(qos_ext(2, false, false)),
        )),
    ));
    out.push(refuse("qos-chain-continues", "unsupported-extension", {
        let mut ext = qos_ext(2, true, true);
        ext.extend_from_slice(&[0x41, 0x00]);
        lone(frame_of(SN0, 2, true, &small(32), Some(ext)))
    }));
    out.push(refuse(
        "extension-id-2",
        "unsupported-extension",
        lone(frame_of(SN0, 2, true, &small(33), Some(std::vec![0x32, 2]))),
    ));
    out.push(Scenario {
        negotiated: false,
        ..refuse(
            "qos-without-negotiation",
            "unsupported-extension",
            lone(frame_of(SN0, 2, true, &small(34), None)),
        )
    });
    out.push(refuse(
        "reliable-frame-gap",
        "sequence-mismatch",
        lone(frame_of(SN0 + 1, 2, true, &small(35), None)),
    ));
    out.push(refuse("reliable-fragment-gap", "fragment-sequence", {
        let parts = f_big(2, true, SN0);
        at_time(std::vec![parts[0].clone(), parts[2].clone()])
    }));
    out.push(refuse(
        "reliable-first-fragment-wrong-sn",
        "sequence-mismatch",
        at_time(f_big(2, true, SN0 + 5)),
    ));
    out.push(refuse(
        "reliable-frame-on-open-lane",
        "unexpected-message",
        {
            let parts = f_big(2, true, SN0);
            at_time(std::vec![
                parts[0].clone(),
                frame_of(SN0 + 1, 2, true, &small(36), None)
            ])
        },
    ));
    out.push(refuse(
        "reliable-lane-limit",
        "lane-limit",
        at_time(interleave(&[
            f_big(1, true, SN0),
            f_big(2, true, SN0),
            f_big(3, true, SN0),
        ])),
    ));
    out.push(refuse(
        "reliable-run-timeout",
        "reassembly-timeout",
        std::vec![
            (0, Step::Batch(f_big(2, true, SN0)[0].clone())),
            (TIMEOUT_MS + 1, Step::Tick),
        ],
    ));
    out.push(refuse(
        "reliable-completed-put-undeclared-key",
        "undeclared-key",
        at_time(fragments_of(&put(38, BIG, OTHER_KEY), SN0, 2, true)),
    ));
    out.push(refuse("best-effort-fragment-empty", "malformed-message", {
        lone(Item {
            lane: (2, false),
            sn: SN0,
            body: fragment_header(false, 2, true, SN0, None),
        })
    }));
    out.push(refuse("reliable-fragment-empty", "malformed-message", {
        lone(Item {
            lane: (2, true),
            sn: SN0,
            body: fragment_header(true, 2, true, SN0, None),
        })
    }));
    out.push(single_run(
        "single-run-best-effort-fragment",
        "unsupported-message",
        at_time(one(&f_big(5, false, SN0)[0])),
    ));
    out.push(single_run(
        "single-run-best-effort-frame",
        "unsupported-message",
        lone(frame_of(SN0, 5, false, &small(39), None)),
    ));
    out.push(single_run(
        "single-run-qos-fragment",
        "unsupported-extension",
        at_time(one(&f_big(2, true, SN0)[0])),
    ));
    out.push(single_run(
        "single-run-qos-frame",
        "unsupported-extension",
        lone(frame_of(SN0, 2, true, &small(41), None)),
    ));
    out
}

// ---------------------------------------------------------------------------------------- the links

type Wire = Rc<RefCell<Pipe>>;

fn wire() -> Wire {
    Rc::new(RefCell::new(Pipe::default()))
}

fn make<const R: usize>(
    role: Role,
    zid: &[u8],
    cookie: &[u8],
    initial_sn: u32,
    rx: &Wire,
    tx: &Wire,
) -> Exam<R> {
    Exam::<R>::with_lanes(
        Scripted {
            rx: rx.clone(),
            tx: tx.clone(),
        },
        role,
        &Config {
            zid,
            lease_ms: LEASE_MS,
            initial_sn,
            cookie,
        },
        Params::from_limits(&HEAP),
        R,
        1,
    )
    .expect("link")
}

fn inject(pipe: &Wire, body: &[u8]) {
    let mut pipe = pipe.borrow_mut();
    pipe.bytes.extend((body.len() as u16).to_le_bytes());
    pipe.bytes.extend(body.iter());
}

fn heap() -> Vec<u8> {
    std::vec![0; 10 * Params::from_limits(&HEAP).message_limit]
}

/// Pumps `b` until it has read what was injected and has nothing queued to send.
fn pump_b<const R: usize>(
    b: &mut Exam<R>,
    handle: LinkHandle,
    now: u64,
    heap: &mut [u8],
) -> Result<(), Error> {
    for _ in 0..32 {
        let report = b.pump_with(handle, now, heap)?;
        if report.batches == 0 && !b.send_pending() {
            return Ok(());
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------------------- the handshakes

/// The cases of the exam: the link's role, its runs, and whether the peer offered the QoS unit extension.
const HANDSHAKES: [(&str, bool, usize, bool); 6] = [
    ("connector-runs-2-peer-accepts", true, 2, true),
    ("connector-runs-2-peer-declines", true, 2, false),
    ("connector-runs-1", true, 1, false),
    ("listener-runs-2-peer-offers", false, 2, true),
    ("listener-runs-2-peer-silent", false, 2, false),
    ("listener-runs-1-peer-offers", false, 1, true),
];

fn peer_message(connector: bool, peer_qos: bool) -> Vec<u8> {
    let mut out = [0u8; 64];
    let written = match (connector, peer_qos) {
        (true, true) => init_ack_qos(&mut out, &PEER_ZID, BATCH as u16, &COOKIE),
        (true, false) => init_ack(&mut out, &PEER_ZID, BATCH as u16, &COOKIE),
        (false, true) => init_syn_qos(&mut out, &PEER_ZID, BATCH as u16),
        (false, false) => init_syn(&mut out, &PEER_ZID, BATCH as u16),
    }
    .expect("peer message");
    out[..written].to_vec()
}

/// What the link wrote, whether the lanes hold, and the class it refused the peer's message with.
fn handshake_run<const R: usize>(
    connector: bool,
    peer_qos: bool,
) -> (String, bool, Option<&'static str>) {
    let (to_link, from_link) = (wire(), wire());
    let (role, cookie): (Role, &[u8]) = if connector {
        (Role::Connector, b"")
    } else {
        (Role::Listener, &COOKIE)
    };
    let mut link = make::<R>(role, &ZID, cookie, SN0, &to_link, &from_link);
    let handle = link.handle();
    let mut wrote = String::new();
    if connector {
        link.open(handle, 0).expect("open");
        wrote = hex(link.last_sent_batch());
    }
    inject(&to_link, &peer_message(connector, peer_qos));
    let mut refused = None;
    match pump_b(&mut link, handle, 0, &mut []) {
        Ok(()) => {}
        Err(Error::Session(error)) => refused = Some(error.class()),
        Err(other) => panic!("the handshake failed with {other:?}"),
    }
    if !connector {
        wrote = hex(link.last_sent_batch());
    }
    (wrote, link.session().lanes(), refused)
}

fn handshake_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for (case, connector, runs, peer_qos) in HANDSHAKES {
        let (wrote, negotiated, refused) = match runs {
            2 => handshake_run::<2>(connector, peer_qos),
            _ => handshake_run::<1>(connector, peer_qos),
        };
        assert_eq!(refused, None, "{case}");
        lines.push(format!(
            "lanes handshake {case} peer={} wrote={wrote} negotiated={}",
            hex(&peer_message(connector, peer_qos)),
            if negotiated { "yes" } else { "no" }
        ));
    }
    // A connector with one run refuses an INIT_ACK that carries the extension.
    let (_, _, refused) = handshake_run::<1>(true, true);
    lines.push(format!(
        "lanes refused connector-runs-1-peer-answers-with-qos {} peer={}",
        refused.expect("a connector with one run refuses the extension"),
        hex(&peer_message(true, true))
    ));
    lines
}

// --------------------------------------------------------------------------------------- the scenarios run

fn cause_name(cause: DropCause) -> String {
    match cause {
        DropCause::Completed(class) => format!("completed:{class}"),
        other => other.name().to_string(),
    }
}

fn run_scenario(scenario: &Scenario) -> Vec<String> {
    match (scenario.runs, scenario.negotiated) {
        (2, true) => go::<2, 2>(scenario),
        (2, false) => go::<2, 1>(scenario),
        _ => go::<1, 1>(scenario),
    }
}

fn settle<const RA: usize, const RB: usize>(
    a: &mut Exam<RA>,
    ha: LinkHandle,
    b: &mut Exam<RB>,
    hb: LinkHandle,
    heap: &mut [u8],
) {
    for _ in 0..200 {
        let from_a = a.pump(ha, 0).expect("a pump");
        let from_b = b.pump_with(hb, 0, heap).expect("b pump");
        if from_a.batches + from_b.batches + from_a.sent_bytes + from_b.sent_bytes == 0
            && !a.send_pending()
            && !b.send_pending()
        {
            return;
        }
    }
    panic!("the pair did not settle");
}

fn go<const RB: usize, const RA: usize>(scenario: &Scenario) -> Vec<String> {
    let (to_b, to_a) = (wire(), wire());
    let mut a = make::<RA>(Role::Connector, &PEER_ZID, b"", SN0, &to_a, &to_b);
    let mut b = make::<RB>(Role::Listener, &ZID, &COOKIE, 1000, &to_b, &to_a);
    let (ha, hb) = (a.handle(), b.handle());
    let mut heap = heap();
    a.open(ha, 0).expect("open");
    settle(&mut a, ha, &mut b, hb, &mut heap);
    assert!(a.is_open() && b.is_open(), "{}: handshake", scenario.name);
    assert_eq!(
        b.session().lanes(),
        scenario.negotiated,
        "{}",
        scenario.name
    );
    b.declare_subscriber(hb, 1, codec::KEY).expect("declare");
    settle(&mut a, ha, &mut b, hb, &mut heap);
    while a.next_notice().is_some() {}
    while b.next_notice().is_some() {}
    while b.take_drop().is_some() {}
    let mut lines = Vec::new();
    let mut touched: BTreeSet<(u8, bool)> = BTreeSet::new();
    for (index, (now, step)) in scenario.events.iter().enumerate() {
        let mut fed: Option<&Item> = None;
        let result = match step {
            Step::Tick => {
                lines.push(format!("lanes tick {} {index} t={now}", scenario.name));
                b.pump_with(hb, *now, &mut heap).map(|_| ())
            }
            Step::Batch(item) => {
                lines.push(format!(
                    "lanes fed {} {index} t={now} len={} sha={}",
                    scenario.name,
                    item.body.len(),
                    &codec::sha(&item.body)[..16]
                ));
                touched.insert(item.lane);
                fed = Some(item);
                inject(&to_b, &item.body);
                pump_b(&mut b, hb, *now, &mut heap)
            }
        };
        match result {
            Ok(()) => {}
            Err(Error::Session(error)) => {
                lines.push(format!("lanes refused {} {}", scenario.name, error.class()));
                assert_eq!(
                    scenario.refused,
                    Some(error.class()),
                    "{} was refused as {}",
                    scenario.name,
                    error.class()
                );
                return lines;
            }
            Err(other) => panic!("{}: the link failed with {other:?}", scenario.name),
        }
        // The session puts the drop of a run ahead of the sample that ended it, and the link keeps drops and
        // notices apart, so the drops of a batch are listed first.
        while let Some((priority, cause)) = b.take_drop() {
            lines.push(format!(
                "lanes drop p{priority} B cause={}",
                cause_name(cause)
            ));
        }
        assert_eq!(b.drops_lost(), 0, "{}: a drop found no room", scenario.name);
        while let Some(notice) = b.next_notice() {
            if let Notice::SampleStored(sample) = notice {
                let item = fed.expect("a sample comes from a batch");
                lines.push(format!(
                    "lanes sample p{} {} sn={} payload={} seq={}",
                    item.lane.0,
                    if item.lane.1 { 'R' } else { 'B' },
                    item.sn,
                    sample.len,
                    sample.sequence
                ));
            }
        }
    }
    assert_eq!(
        scenario.refused, None,
        "{} was never refused",
        scenario.name
    );
    let counts: Vec<String> = touched
        .iter()
        .map(|(priority, reliable)| {
            format!(
                "p{priority}{}={}",
                if *reliable { 'R' } else { 'B' },
                b.session().lane_next(Lane {
                    priority: *priority,
                    reliable: *reliable
                })
            )
        })
        .collect();
    lines.push(format!(
        "lanes counters {} {}",
        scenario.name,
        counts.join(" ")
    ));
    lines.push(format!("lanes ok {}", scenario.name));
    lines
}

/// Runs the whole exam and prints its transcript.
pub(super) fn run() {
    let mut lines = handshake_lines();
    for scenario in scenarios() {
        lines.extend(run_scenario(&scenario));
    }
    for line in lines {
        println!("[zenoh-exam] {line}");
    }
}
