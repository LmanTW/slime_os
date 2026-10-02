//! Host tests for the transport runtime over a scripted byte link.

use super::*;
use crate::zenoh_profile0::{decode_batch, encode};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const SAMPLES: [&str; 4] = [
    "00010000000000000a000000",
    "000100000100000014000000",
    "00010000020000001e000000",
    "000100000300000028000000",
];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
    closed: bool,
}

#[derive(Clone, Default)]
struct Knobs {
    /// Most bytes one `send` accepts; 0 accepts none.
    send_cap: Option<usize>,
    /// Most bytes one `recv` returns.
    recv_cap: Option<usize>,
}

/// One end of a scripted stream: it reads `rx` and writes `tx`.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    tx: Rc<RefCell<Pipe>>,
    knobs: Rc<RefCell<Knobs>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let cap = self.knobs.borrow().send_cap;
        let take = cap.map_or(buf.len(), |cap| cap.min(buf.len()));
        let mut pipe = self.tx.borrow_mut();
        if pipe.closed {
            return Err(LinkError::Closed);
        }
        pipe.bytes.extend(buf.iter().take(take));
        Ok(take)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        let cap = self.knobs.borrow().recv_cap;
        let mut pipe = self.rx.borrow_mut();
        let take = cap.map_or(buf.len(), |cap| cap.min(buf.len()));
        let mut count = 0;
        while count < take.min(buf.len()) {
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
        let pipe = self.rx.borrow();
        pipe.closed && pipe.bytes.is_empty()
    }
}

struct Pair {
    a: Link<Scripted>,
    b: Link<Scripted>,
    ha: LinkHandle,
    hb: LinkHandle,
    a_to_b: Rc<RefCell<Pipe>>,
    a_knobs: Rc<RefCell<Knobs>>,
    b_knobs: Rc<RefCell<Knobs>>,
}

fn config(zid: &[u8], cookie: &[u8], initial_sn: u32) -> Config<'static> {
    // The slices are leaked for the test's lifetime so a `Config` can be returned by value.
    Config {
        zid: Vec::leak(zid.to_vec()),
        lease_ms: 2000,
        initial_sn,
        cookie: Vec::leak(cookie.to_vec()),
    }
}

fn pair(generation: u32) -> Pair {
    // A restart draws a new initial sequence number, so a predecessor's frames do not line up.
    let initial_sn = generation.wrapping_sub(1).wrapping_mul(1000);
    let a_to_b = Rc::new(RefCell::new(Pipe::default()));
    let b_to_a = Rc::new(RefCell::new(Pipe::default()));
    let a_knobs = Rc::new(RefCell::new(Knobs::default()));
    let b_knobs = Rc::new(RefCell::new(Knobs::default()));
    let a_io = Scripted {
        rx: b_to_a.clone(),
        tx: a_to_b.clone(),
        knobs: a_knobs.clone(),
    };
    let b_io = Scripted {
        rx: a_to_b.clone(),
        tx: b_to_a.clone(),
        knobs: b_knobs.clone(),
    };
    let a = Link::new(
        a_io,
        Role::Connector,
        &config(&[0xa1, 0xa2], b"", initial_sn),
        generation,
    )
    .expect("connector");
    let b = Link::new(
        b_io,
        Role::Listener,
        &config(&[0xb1, 0xb2], b"cookie-b", initial_sn),
        generation,
    )
    .expect("listener");
    let (ha, hb) = (a.handle(), b.handle());
    Pair {
        a,
        b,
        ha,
        hb,
        a_to_b,
        a_knobs,
        b_knobs,
    }
}

impl Pair {
    /// Pumps both ends until neither moves a byte or reads a batch.
    fn run(&mut self, now: u64) {
        for _ in 0..400 {
            let a = self.a.pump(self.ha, now).expect("a pump");
            let b = self.b.pump(self.hb, now).expect("b pump");
            let quiet = a.batches + b.batches + a.sent_bytes + b.sent_bytes == 0
                && !self.a.send_pending()
                && !self.b.send_pending();
            if quiet {
                return;
            }
        }
        panic!("the pair did not settle");
    }

    fn open(&mut self) {
        self.a.open(self.ha, 0).expect("open");
        self.run(0);
        assert!(self.a.is_open() && self.b.is_open(), "handshake");
    }
}

fn notices<L: ByteLink>(link: &mut Link<L>) -> Vec<Notice> {
    let mut all = Vec::new();
    while let Some(notice) = link.next_notice() {
        all.push(notice);
    }
    all
}

fn attachment(sequence: i64) -> [u8; 33] {
    encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment")
}

fn delivered(list: &[Notice]) -> Vec<(i64, Vec<u8>)> {
    list.iter()
        .filter_map(|notice| match notice {
            Notice::SampleDelivered(sample) => Some((sample.sequence, sample.payload().to_vec())),
            _ => None,
        })
        .collect()
}

/// Declares the demo key on `b` and publishes the four samples from `a`, settling after each.
fn exchange(pair: &mut Pair) -> Vec<Notice> {
    pair.b.declare_subscriber(pair.hb, 1, KEY).expect("declare");
    pair.run(1);
    for (index, hexed) in SAMPLES.iter().enumerate() {
        pair.a
            .publish(pair.ha, KEY, &attachment(index as i64 + 1), &unhex(hexed))
            .expect("publish");
        pair.run(2 + index as u64);
    }
    notices(&mut pair.b)
}

#[test]
fn connector_opens_and_publishes() {
    let mut pair = pair(1);
    pair.open();
    assert!(notices(&mut pair.a).contains(&Notice::HandshakeComplete));
    assert!(notices(&mut pair.b).contains(&Notice::HandshakeComplete));
    // The subscriber declares; the connector, the publisher, learns of it before it publishes.
    pair.b.declare_subscriber(pair.hb, 1, KEY).expect("declare");
    pair.run(1);
    assert!(notices(&mut pair.a).contains(&Notice::SubscriberDeclared { id: 1 }));
    assert_eq!(pair.a.session().peer_subscriber_key(), Some(KEY));
    for (index, hexed) in SAMPLES.iter().enumerate() {
        pair.a
            .publish(pair.ha, KEY, &attachment(index as i64 + 1), &unhex(hexed))
            .expect("publish");
        pair.run(2 + index as u64);
    }
    assert_eq!(delivered(&notices(&mut pair.b)).len(), 4);
    println!("[zenoh-exam] link ok connector-opens-and-publishes");
}

#[test]
fn listener_accepts_and_delivers() {
    let mut pair = pair(1);
    pair.open();
    let seen = exchange(&mut pair);
    let got = delivered(&seen);
    assert_eq!(got.len(), 4, "four samples delivered: {seen:?}");
    for (index, (sequence, payload)) in got.iter().enumerate() {
        assert_eq!(*sequence, index as i64 + 1);
        assert_eq!(payload, &unhex(SAMPLES[index]));
    }
    println!("[zenoh-exam] link ok listener-accepts-and-delivers");
}

/// A listener that has finished its handshake and declared the demo key, plus the framed
/// bytes a connector in the same state writes for the four samples.
fn ready_listener_and_stream() -> (Pair, Vec<u8>) {
    let mut pair = pair(1);
    pair.open();
    pair.b.declare_subscriber(pair.hb, 1, KEY).expect("declare");
    pair.run(1);
    let _ = notices(&mut pair.a);
    let _ = notices(&mut pair.b);
    let mut stream = Vec::new();
    for (index, hexed) in SAMPLES.iter().enumerate() {
        pair.a
            .publish(pair.ha, KEY, &attachment(index as i64 + 1), &unhex(hexed))
            .expect("publish");
        pair.a.pump(pair.ha, 2).expect("flush");
        stream.extend(pair.a_to_b.borrow_mut().bytes.drain(..));
    }
    (pair, stream)
}

/// Feeds `chunks` to the listener of a freshly built, identical session and returns what it delivered.
fn deliver(chunks: &[&[u8]]) -> Vec<(i64, Vec<u8>)> {
    let (mut pair, _) = ready_listener_and_stream();
    let mut got = Vec::new();
    for chunk in chunks {
        pair.a_to_b.borrow_mut().bytes.extend(chunk.iter());
        for _ in 0..40 {
            pair.b.pump(pair.hb, 3).expect("b pump");
        }
        got.extend(delivered(&notices(&mut pair.b)));
    }
    got
}

#[test]
fn split_and_coalesced_batches() {
    let (_, stream) = ready_listener_and_stream();
    let expected: Vec<(i64, Vec<u8>)> = SAMPLES
        .iter()
        .enumerate()
        .map(|(i, h)| (i as i64 + 1, unhex(h)))
        .collect();
    assert!(stream.len() > 4 * 150, "four framed pushes");

    // The whole stream in one read delivers every sample, in order.
    assert_eq!(deliver(&[&stream]), expected, "one coalesced read");
    // Cut at every offset, the same samples arrive in the same order.
    for at in 1..stream.len() {
        assert_eq!(
            deliver(&[&stream[..at], &stream[at..]]),
            expected,
            "split at {at}"
        );
    }
    println!("[zenoh-exam] link ok split-and-coalesced-batches");
}

#[test]
fn backpressure_resumes() {
    let mut pair = pair(1);
    pair.a_knobs.borrow_mut().send_cap = Some(3);
    pair.b_knobs.borrow_mut().send_cap = Some(3);
    pair.b_knobs.borrow_mut().recv_cap = Some(5);
    pair.open();
    let seen = exchange(&mut pair);
    assert_eq!(
        delivered(&seen).len(),
        4,
        "every sample crossed small writes"
    );
    println!("[zenoh-exam] link ok backpressure-resumes");
}

#[test]
fn peer_close_ends_session() {
    let mut pair = pair(1);
    pair.open();
    pair.a.close(pair.ha, 0).expect("close");
    pair.a.pump(pair.ha, 5).expect("flush the close");
    pair.b.pump(pair.hb, 5).expect("b reads the close");
    assert!(
        notices(&mut pair.b)
            .iter()
            .any(|n| matches!(n, Notice::Closed { .. }))
    );
    assert!(pair.a.is_closed());
    println!("[zenoh-exam] link ok peer-close-ends-session");
}

#[test]
fn restart_uses_fresh_session() {
    let (first, stream) = ready_listener_and_stream();
    let old = first.ha;
    assert!(!stream.is_empty());

    // The successor opens its own handshake from scratch under generation 2.
    let mut second = pair(2);
    assert!(!second.a.is_open(), "a new link starts closed to traffic");
    second.open();
    assert!(notices(&mut second.a).contains(&Notice::HandshakeComplete));
    assert!(notices(&mut second.b).contains(&Notice::HandshakeComplete));
    second
        .b
        .declare_subscriber(second.hb, 1, KEY)
        .expect("declare");
    second.run(1);
    let _ = notices(&mut second.a);

    // Bytes the predecessor wrote cannot be replayed into the successor: its frames carry
    // sequence numbers the new session does not expect, so nothing is delivered and the link ends.
    second.a_to_b.borrow_mut().bytes.extend(stream.iter());
    let replay = second.b.pump(second.hb, 4);
    assert!(
        replay.is_err() || delivered(&notices(&mut second.b)).is_empty(),
        "a replayed frame was delivered"
    );
    assert!(second.b.is_closed() || replay.is_ok());

    // The predecessor's handle is refused on the successor.
    assert_eq!(
        second
            .a
            .publish(old, KEY, &attachment(1), &unhex(SAMPLES[0])),
        Err(Error::StaleHandle)
    );
    println!("[zenoh-exam] link ok restart-uses-fresh-session");
}

fn inject(pair: &Pair, bytes: &[u8]) {
    pair.a_to_b.borrow_mut().bytes.extend(bytes.iter());
}

#[test]
fn refusals() {
    // oversized-length-prefix
    let mut p = pair(1);
    p.open();
    inject(&p, &[0x01, 0x10]);
    assert_eq!(
        p.b.pump(p.hb, 9).expect_err("oversized"),
        Error::Stream(Refusal::LengthExceedsBatch)
    );
    assert!(p.b.is_closed());
    println!("[zenoh-exam] link refused oversized-length-prefix");

    // zero-length-prefix
    let mut p = pair(1);
    p.open();
    inject(&p, &[0x00, 0x00]);
    assert_eq!(
        p.b.pump(p.hb, 9).expect_err("zero"),
        Error::Stream(Refusal::EmptyBatch)
    );
    println!("[zenoh-exam] link refused zero-length-prefix");

    // garbage-after-open
    let mut p = pair(1);
    p.open();
    let garbage = [0xffu8; 6];
    let mut framed = [0u8; 64];
    let n = encode::stream_batch(&mut framed, &garbage).expect("frame");
    inject(&p, &framed[..n]);
    assert!(p.b.pump(p.hb, 9).is_err());
    assert!(p.b.is_closed());
    println!("[zenoh-exam] link refused garbage-after-open");

    // receive-queue-full: with the send slot busy no batch can be consumed, so the runtime must
    // stop reading at its queue bound and leave the rest in the stream rather than drop it.
    let mut p = pair(1);
    p.open();
    p.b_knobs.borrow_mut().send_cap = Some(0);
    p.b.declare_subscriber(p.hb, 1, KEY).expect("declare");
    let mut stream = Vec::new();
    for _ in 0..8 {
        let mut body = [0u8; 8];
        let n = encode::close(&mut body, 0, false).expect("close");
        let mut framed = [0u8; 16];
        let m = encode::stream_batch(&mut framed, &body[..n]).expect("frame");
        stream.extend_from_slice(&framed[..m]);
    }
    let offered = stream.len();
    inject(&p, &stream);
    let report = p.b.pump(p.hb, 9).expect("pump");
    let left = p.a_to_b.borrow().bytes.len();
    assert_eq!(report.received_bytes + left, offered, "no byte was dropped");
    assert!(report.received_bytes <= STREAM_LENGTH_BYTES + MAX_BATCH_BYTES);
    // Larger than the queue: more than one reassembly buffer's worth stays unread.
    let mut p = pair(1);
    p.open();
    p.b_knobs.borrow_mut().send_cap = Some(0);
    p.b.declare_subscriber(p.hb, 1, KEY).expect("declare");
    inject(&p, &stream.repeat(40));
    let offered = stream.len() * 40;
    let report = p.b.pump(p.hb, 9).expect("pump");
    assert!(
        report.received_bytes < offered,
        "the runtime stopped at its bound"
    );
    assert_eq!(
        report.received_bytes + p.a_to_b.borrow().bytes.len(),
        offered
    );
    println!("[zenoh-exam] link refused receive-queue-full");

    // retry-limit-reached
    let mut p = pair(1);
    p.a_knobs.borrow_mut().send_cap = Some(0);
    p.a.open(p.ha, 0).expect("open");
    let mut result = Ok(PumpReport::default());
    for _ in 0..=MAX_RETRIES + 1 {
        result = p.a.pump(p.ha, 1);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result.expect_err("stalled"), Error::RetryLimit);
    println!("[zenoh-exam] link refused retry-limit-reached");

    // send-after-close
    let mut p = pair(1);
    p.open();
    p.a.close(p.ha, 0).expect("close");
    assert_eq!(
        p.a.publish(p.ha, KEY, &attachment(1), &unhex(SAMPLES[0])),
        Err(Error::SendAfterClose)
    );
    println!("[zenoh-exam] link refused send-after-close");

    // stale-session-handle
    let old = pair(1).ha;
    let mut p = pair(2);
    p.open();
    assert_eq!(
        p.a.publish(old, KEY, &attachment(1), &unhex(SAMPLES[0])),
        Err(Error::StaleHandle)
    );
    println!("[zenoh-exam] link refused stale-session-handle");
}

#[test]
fn taps_hold_the_exact_batches_exchanged() {
    let mut pair = pair(1);
    pair.open();
    pair.b.declare_subscriber(pair.hb, 1, KEY).expect("declare");
    pair.run(1);
    let attachment = attachment(1);
    let payload = unhex(SAMPLES[0]);
    pair.a
        .publish(pair.ha, KEY, &attachment, &payload)
        .expect("publish");
    let sent = pair.a.last_sent_batch().to_vec();
    pair.run(2);
    assert_eq!(pair.b.last_received_batch(), sent.as_slice());
    // The tap is the batch body, not the framed bytes: no stream prefix.
    assert_eq!(
        decode_batch(&sent).map(|m| matches!(m, crate::zenoh_profile0::Message::Frame(_))),
        Ok(true)
    );
}

#[test]
fn the_received_tap_names_the_batch_behind_each_notice() {
    let (mut pair, stream) = ready_listener_and_stream();
    // All four framed samples arrive in one read; each pump must expose exactly one of them.
    pair.a_to_b.borrow_mut().bytes.extend(stream.iter());
    let mut seen = Vec::new();
    for _ in 0..40 {
        pair.b.pump(pair.hb, 3).expect("pump");
        while let Some(notice) = pair.b.next_notice() {
            if let Notice::SampleDelivered(sample) = notice {
                seen.push((sample.sequence, pair.b.last_received_batch().to_vec()));
            }
        }
    }
    assert_eq!(seen.len(), 4);
    for (index, (sequence, batch)) in seen.iter().enumerate() {
        assert_eq!(*sequence, index as i64 + 1);
        let frame = decode_batch(batch).expect("batch");
        let crate::zenoh_profile0::Message::Frame(frame) = frame else {
            panic!("not a frame");
        };
        assert_eq!(
            frame.sn, index as u32,
            "the tap held another sample's batch"
        );
    }
}
