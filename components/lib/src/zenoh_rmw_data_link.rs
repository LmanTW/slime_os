//! The rmw data link exam: a graph link that serves its owner's one subscription, against the two data sessions
//! an rmw_zenoh_cpp 0.6.10 peer exchanged with a Slime-side peer.
//!
//! The captured bytes are `zenoh_rmw_data::fixtures`, generated from `contracts/zenoh-rmw-data/v1`. This module
//! writes them to a link through a scripted byte stream and prints one `[zenoh-exam] datalink ...` line for each
//! thing it did. The checker builds the same transcript from the captured bytes and `zenoh_wire`, and owns what
//! each line must be, in what order, and which class each refusal is.

use crate::zenoh_link::{ByteLink, LinkError};
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::encode::FrameEncoder;
use crate::zenoh_profile0::session::{Config, Params, Role};
use crate::zenoh_profile0::{Bounds, Mapping};
use crate::zenoh_rmw_data::fixtures::{PEERPUB, SLIMEPUB};
use crate::zenoh_rmw_link::{GraphHandle, GraphLinkError, GraphLinkOf};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::format;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const FRAMED: usize = 512;
const SLOTS: usize = 32;
const KEY_BYTES: usize = 253;
const ENTITIES: usize = 16;
const QUEUE: usize = 16;
const SMALL_QUEUE: usize = 4;
const SLOT_BYTES: usize = 32;
const DOMAIN: u64 = 0;
const SUBSCRIPTION_ID: u32 = 1;
const PEER_SUBSCRIBER_ID: u32 = 23;
const SENT: usize = 8;
const HANDSHAKE_BATCHES: usize = 2;
/// The batches of the listener's capture up to and including the one that carries the INTEREST.
const INTEREST_BATCH: usize = 5;
const PAYLOAD_BOUND: usize = 22;
const KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const OTHER_KEY: &str = "0/other/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const COOKIE: &[u8] = b"slime-rmw-capture-cookie-01";
const ZID: [u8; 16] = [
    0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];

type Wide = GraphLinkOf<Scripted, FRAMED, SLOTS, SLOTS, KEY_BYTES, ENTITIES, QUEUE, SLOT_BYTES>;
type Small =
    GraphLinkOf<Scripted, FRAMED, SLOTS, SLOTS, KEY_BYTES, ENTITIES, SMALL_QUEUE, SLOT_BYTES>;

fn line(text: &str) {
    std::println!("[zenoh-exam] datalink {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("-");
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn framed(batch: &[u8]) -> Vec<u8> {
    let mut out = (batch.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(batch);
    out
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
    String::from_utf8(payload[8..payload.len() - 1].to_vec()).expect("UTF-8 text")
}

fn attachment(number: usize) -> [u8; 33] {
    encode::attachment(number as i64 + 1, 1_000_000_000 + number as i64, &GID)
        .expect("an attachment")
}

// ------------------------------------------------------------------------------------ the byte stream

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

/// One end of a scripted stream: it reads what the exam feeds it and logs every byte the link writes.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    budget: Rc<RefCell<Option<usize>>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let left = *self.budget.borrow();
        let take = left.map_or(buf.len(), |left| left.min(buf.len()));
        if let Some(left) = left {
            *self.budget.borrow_mut() = Some(left - take);
        }
        self.wrote.borrow_mut().extend_from_slice(&buf[..take]);
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

struct Rig<L> {
    link: L,
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    budget: Rc<RefCell<Option<usize>>>,
}

fn config() -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: 30_000,
        initial_sn: 7,
        cookie: COOKIE,
    }
}

fn params(payload: usize) -> Params {
    let mut params = Params::GRAPH;
    params.bounds.payload = payload;
    params
}

macro_rules! rig {
    ($ty:ty, $params:expr, $generation:expr) => {{
        let rx = Rc::new(RefCell::new(Pipe::default()));
        let wrote = Rc::new(RefCell::new(Vec::new()));
        let budget = Rc::new(RefCell::new(None));
        let io = Scripted {
            rx: rx.clone(),
            wrote: wrote.clone(),
            budget: budget.clone(),
        };
        let link = <$ty>::new(io, Role::Listener, &config(), $params, DOMAIN, $generation)
            .expect("a data link");
        Rig {
            link,
            rx,
            wrote,
            budget,
        }
    }};
}

macro_rules! rig_methods {
    ($ty:ty) => {
        #[allow(dead_code)]
        impl Rig<$ty> {
            fn written(&self) -> Vec<u8> {
                self.wrote.borrow().clone()
            }

            fn handle(&self) -> GraphHandle {
                self.link.handle()
            }

            fn feed(&self, bytes: &[u8]) {
                self.rx.borrow_mut().bytes.extend(bytes.iter().copied());
            }

            fn pump(&mut self) -> Result<(), GraphLinkError> {
                let handle = self.link.handle();
                self.link.pump(handle, 0).map(|_| ())
            }

            /// Pumps until a pump neither reads nor writes and no batch waits in the send slot.
            fn settle(&mut self) {
                for _ in 0..4000 {
                    let handle = self.link.handle();
                    let report = self
                        .link
                        .pump(handle, 0)
                        .expect("the link takes the stream");
                    let quiet = report.batches + report.sent_bytes == 0
                        && !self.link.send_pending()
                        && self.rx.borrow().bytes.is_empty();
                    if quiet {
                        return;
                    }
                }
                panic!("the link did not settle");
            }

            fn feed_batch(&mut self, batch: &[u8]) {
                self.feed(&framed(batch));
                self.settle();
            }

            fn handshake(&mut self, rows: &[(&str, &str)]) {
                for (_name, hexed) in &rows[..HANDSHAKE_BATCHES] {
                    self.feed_batch(&unhex(hexed));
                }
            }

            fn close(&mut self) -> Vec<u8> {
                let before = self.written().len();
                let handle = self.handle();
                self.link.close(handle, 0).expect("a local close");
                self.settle();
                self.written()[before..].to_vec()
            }

            /// The Put a listener's peer asks for, tried until the peer's subscriber arrives, then all eight.
            fn try_puts(&mut self) -> bool {
                let handle = self.handle();
                let first = cdr_string("Hello Slime 0");
                match self.link.send_put(handle, KEY, &attachment(0), &first) {
                    Ok(()) => {}
                    Err(error) => {
                        assert_eq!(
                            error.class(),
                            "undeclared-key",
                            "only an absent subscriber stops a Put"
                        );
                        return false;
                    }
                }
                self.settle();
                for number in 1..SENT {
                    let payload = cdr_string(&format!("Hello Slime {number}"));
                    self.link
                        .send_put(handle, KEY, &attachment(number), &payload)
                        .expect("a Put on the peer's subscriber");
                    self.settle();
                }
                true
            }
        }
    };
}

rig_methods!(Wide);
rig_methods!(Small);

// ------------------------------------------------------------------------------------------ the groups

const MODES: [&str; 3] = ["whole", "bytewise", "coalesced"];

/// A captured session, written in one of three ways. The handshake goes whole in every way, because the owner's
/// subscription is declared between it and the first FRAME. A listener's Puts are written once the peer's
/// subscriber is in, which a Put on its key finds out.
fn write_session<R>(rig: &mut R, group: &str, rows: &[(&str, &str)], mode: &str) -> bool
where
    R: Session,
{
    rig.shake(rows);
    if group == "peerpub" {
        rig.subscribe();
    }
    let rest: Vec<Vec<u8>> = rows[HANDSHAKE_BATCHES..]
        .iter()
        .map(|(_name, hexed)| unhex(hexed))
        .collect();
    let mut puts = false;
    match mode {
        "whole" => {
            for batch in &rest {
                rig.batch(batch);
                if group == "slimepub" && !puts {
                    puts = rig.puts();
                }
            }
        }
        "bytewise" => {
            for batch in &rest {
                for byte in framed(batch) {
                    rig.byte(byte);
                }
                rig.settled();
                if group == "slimepub" && !puts {
                    puts = rig.puts();
                }
            }
        }
        _ => {
            let all: Vec<u8> = rest.iter().flat_map(|batch| framed(batch)).collect();
            rig.bulk(&all);
            if group == "slimepub" {
                puts = rig.puts();
            }
        }
    }
    puts
}

trait Session {
    fn shake(&mut self, rows: &[(&str, &str)]);
    fn subscribe(&mut self);
    fn batch(&mut self, batch: &[u8]);
    fn byte(&mut self, byte: u8);
    fn bulk(&mut self, bytes: &[u8]);
    fn settled(&mut self);
    fn puts(&mut self) -> bool;
}

macro_rules! session_impl {
    ($ty:ty) => {
        impl Session for Rig<$ty> {
            fn shake(&mut self, rows: &[(&str, &str)]) {
                self.handshake(rows);
            }
            fn subscribe(&mut self) {
                let handle = self.handle();
                self.link
                    .declare_subscriber(handle, SUBSCRIPTION_ID, KEY)
                    .expect("the owner's subscription");
                self.settle();
            }
            fn batch(&mut self, batch: &[u8]) {
                self.feed_batch(batch);
            }
            fn byte(&mut self, byte: u8) {
                self.feed(&[byte]);
                self.pump().expect("the link took the byte");
            }
            fn bulk(&mut self, bytes: &[u8]) {
                self.feed(bytes);
                self.settle();
            }
            fn settled(&mut self) {
                self.settle();
            }
            fn puts(&mut self) -> bool {
                self.try_puts()
            }
        }
    };
}

session_impl!(Wide);
session_impl!(Small);

fn replay_groups() {
    for (group, rows) in [("peerpub", &PEERPUB[..]), ("slimepub", &SLIMEPUB[..])] {
        for mode in MODES {
            let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
            let puts = write_session(&mut rig, group, rows, mode);
            assert_eq!(
                puts,
                group == "slimepub",
                "{group} {mode}: the listener's Puts were written"
            );
            assert!(
                rig.link.is_open(),
                "{group} {mode}: the link is open until a local close"
            );
            line(&format!("sent {group} {mode} {}", hex(&rig.written())));
            let mut samples = 0;
            while let Some(sample) = rig.link.pop_sample() {
                samples += 1;
                line(&format!(
                    "sample {group} {mode} {} {} {} {}",
                    sample.subscription,
                    sample.sequence,
                    sample.timestamp,
                    read_string(sample.payload()).replace(' ', "_")
                ));
            }
            if group == "slimepub" {
                line(&format!("sample-none {group} {mode} {samples}"));
            }
            line(&format!(
                "pushes {group} {mode} dropped={} queue-dropped={}",
                rig.link.dropped_pushes(),
                rig.link.queue_dropped()
            ));
            let wrote = rig.close();
            let reason = rig.link.close_reason().expect("a closed link has a reason");
            let subscription = rig
                .link
                .subscription()
                .map_or(String::from("none"), |id| id.to_string());
            line(&format!(
                "closed {group} {mode} reason={reason} wrote={} queue={} subscription={subscription}",
                hex(&wrote),
                rig.link.queued()
            ));
            line(&format!("ok {group}-{mode}"));
        }
    }
}

// --------------------------------------------------------------------------------------- the queue

/// A frame of Puts on the owner's key that the peer could send after the handshake, with the sequence number
/// the peer's first FRAME carries.
fn peer_put(sn: u32, number: usize, text: &str) -> Vec<u8> {
    let mut out = std::vec![0x25];
    leb(&mut out, sn);
    out.push(0x7d);
    leb(&mut out, 0);
    leb(&mut out, KEY.len() as u32);
    out.extend_from_slice(KEY.as_bytes());
    // A Put with the extension flag, then the attachment extension: id 3, a ZBuf.
    out.push(0x81);
    out.push(0x43);
    let raw = attachment(number);
    leb(&mut out, raw.len() as u32);
    out.extend_from_slice(&raw);
    let payload = cdr_string(text);
    leb(&mut out, payload.len() as u32);
    out.extend_from_slice(&payload);
    out
}

fn first_sn(rows: &[(&str, &str)]) -> u32 {
    let batch = unhex(rows[HANDSHAKE_BATCHES].1);
    let mut at = 1;
    let (mut value, mut shift) = (0u32, 0);
    loop {
        let byte = batch[at];
        at += 1;
        value |= u32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return value;
        }
    }
}

fn queue_scenarios() {
    let mut small: Rig<Small> = rig!(Small, Params::GRAPH, 1);
    write_session(&mut small, "peerpub", &PEERPUB, "whole");
    let held = small.link.queued();
    let dropped = small.link.queue_dropped();
    let mut sequences = Vec::new();
    while let Some(sample) = small.link.pop_sample() {
        sequences.push(sample.sequence.to_string());
    }
    line(&format!(
        "queue small held={held} dropped={dropped} sequences={}",
        sequences.join(",")
    ));

    let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    rig.handshake(&PEERPUB);
    rig.subscribe();
    let sn = first_sn(&PEERPUB);
    rig.feed_batch(&peer_put(sn, 0, &"x".repeat(SLOT_BYTES)));
    rig.feed_batch(&peer_put(sn + 1, 1, "Hello World: 2"));
    let held = rig.link.queued();
    let dropped = rig.link.queue_dropped();
    let sample = rig.link.pop_sample().expect("the sample that fits");
    line(&format!(
        "queue oversize held={held} dropped={dropped} sequence={} open={}",
        sample.sequence,
        rig.link.is_open()
    ));

    let mut ended: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    write_session(&mut ended, "peerpub", &PEERPUB, "whole");
    let before = ended.link.queued();
    ended.close();
    line(&format!(
        "queue ended before={before} after={}",
        ended.link.queued()
    ));
}

// ------------------------------------------------------------------------------------------ the refusals

/// A listener that took the first five batches of the listener's capture, the last of which carries the INTEREST,
/// and then the subscriber the peer declares on the chatter key, written here because the capture's own
/// subscriber arrives behind pushes a bounded payload would refuse.
fn peer_subscribed(payload_bound: usize) -> Rig<Wide> {
    let mut rig: Rig<Wide> = rig!(Wide, params(payload_bound), 1);
    for (_name, hexed) in &SLIMEPUB[..INTEREST_BATCH] {
        rig.feed_batch(&unhex(hexed));
    }
    let mut storage = [0u8; 512];
    let mut frame = FrameEncoder::with_bounds(
        &mut storage,
        rig.link.session().expected_rx_sn(),
        Bounds {
            batch: 400,
            key: KEY_BYTES,
            payload: 512,
        },
    )
    .expect("a frame");
    frame
        .declare_subscriber(PEER_SUBSCRIBER_ID, Mapping::Sender, KEY)
        .expect("a subscriber declaration");
    let length = frame.finish().expect("a frame");
    let batch = storage[..length].to_vec();
    rig.feed_batch(&batch);
    rig
}

fn refused(name: &str, error: GraphLinkError, rig: &Rig<Wide>) {
    line(&format!(
        "refused {name} {} {}",
        error.class(),
        hex(&rig.written())
    ));
}

fn refusals() {
    // A second subscription, once the first reached the stream.
    let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    rig.handshake(&SLIMEPUB);
    rig.subscribe();
    let handle = rig.handle();
    let error = rig
        .link
        .declare_subscriber(handle, 2, OTHER_KEY)
        .expect_err("a second subscription");
    refused("second-subscription", error, &rig);

    // A declaration behind one that never reached the stream.
    let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    rig.handshake(&SLIMEPUB);
    let handle = rig.handle();
    rig.link
        .declare_subscriber(handle, SUBSCRIPTION_ID, KEY)
        .expect("the first declaration is queued");
    let error = rig
        .link
        .declare_subscriber(handle, 2, OTHER_KEY)
        .expect_err("a declaration behind a waiting batch");
    refused("subscribe-while-the-slot-is-busy", error, &rig);

    let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    rig.handshake(&SLIMEPUB);
    let handle = rig.handle();
    let payload = cdr_string("Hello Slime 0");
    let error = rig
        .link
        .send_put(handle, KEY, &attachment(0), &payload)
        .expect_err("a Put before the peer subscribes");
    refused("put-before-the-peer-subscribes", error, &rig);

    let mut rig = peer_subscribed(512);
    let handle = rig.handle();
    let error = rig
        .link
        .send_put(handle, OTHER_KEY, &attachment(0), &payload)
        .expect_err("a Put on another key");
    refused("put-on-another-key", error, &rig);

    // The longest string the bound takes is sent by the session, so the bound is what refuses the next one.
    let mut fits = peer_subscribed(PAYLOAD_BOUND);
    let handle = fits.handle();
    fits.link
        .send_put(handle, KEY, &attachment(0), &payload)
        .expect("a string of the bound is queued");
    let mut bounded = peer_subscribed(PAYLOAD_BOUND);
    let handle = bounded.handle();
    let error = bounded
        .link
        .send_put(handle, KEY, &attachment(1), &cdr_string("Hello Slime 00"))
        .expect_err("a Put over the payload bound");
    refused("put-over-the-payload-bound", error, &bounded);

    // A Put behind the answer to the INTEREST, which the stream has not taken.
    let mut rig: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    rig.handshake(&SLIMEPUB);
    *rig.budget.borrow_mut() = Some(0);
    for (_name, hexed) in &SLIMEPUB[HANDSHAKE_BATCHES..INTEREST_BATCH] {
        rig.feed(&framed(&unhex(hexed)));
    }
    rig.pump()
        .expect("one pump against a stream that takes nothing");
    assert!(rig.link.send_pending(), "the answer waits in the send slot");
    let handle = rig.handle();
    let error = rig
        .link
        .send_put(handle, KEY, &attachment(0), &payload)
        .expect_err("a Put behind a waiting batch");
    refused("put-while-the-slot-is-busy", error, &rig);

    // A handle of an earlier generation.
    let mut current: Rig<Wide> = rig!(Wide, Params::GRAPH, 2);
    current.handshake(&SLIMEPUB);
    let earlier: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    let stale = earlier.handle();
    let error = current
        .link
        .declare_subscriber(stale, SUBSCRIPTION_ID, KEY)
        .expect_err("a stale handle");
    refused("stale-handle", error, &current);

    // A call after a local close.
    let mut closed: Rig<Wide> = rig!(Wide, Params::GRAPH, 1);
    closed.handshake(&SLIMEPUB);
    closed.close();
    let handle = closed.handle();
    let error = closed
        .link
        .declare_subscriber(handle, SUBSCRIPTION_ID, KEY)
        .expect_err("a call after close");
    refused("send-after-close", error, &closed);
}

/// Every section, in the order the exam lists them.
#[test]
fn the_data_link_exam() {
    replay_groups();
    queue_scenarios();
    refusals();
}
