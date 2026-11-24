//! Host tests for a heap link that holds several reassembly runs: which heap cell each run is joined into, and
//! what a tick reports while a best-effort run is late.

mod exam;

use crate::zenoh_link::{ByteLink, Error, LinkError, LinkHandle, LinkOf, Notice};
use crate::zenoh_profile0::fragment::tests as codec;
use crate::zenoh_profile0::limits::HEAP;
use crate::zenoh_profile0::session::{Config, Params, Role, SessionError};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    tx: Rc<RefCell<Pipe>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        self.tx.borrow_mut().bytes.extend(buf.iter());
        Ok(buf.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        let mut pipe = self.rx.borrow_mut();
        let take = buf.len().min(pipe.bytes.len());
        for (slot, byte) in buf.iter_mut().zip(pipe.bytes.drain(..take)) {
            *slot = byte;
        }
        Ok(take)
    }

    fn eof(&self) -> bool {
        false
    }
}

const LEASE_MS: u64 = 8000;
const FIRST_SN: u32 = 1000;
/// The pieces a message is cut into: well inside the 2048-byte batch.
const PIECE: usize = 1000;

type Link2 = LinkOf<Scripted, 2048, 4, 5, 129, 0, 8, 4, 2>;

fn config(cookie: &'static [u8]) -> Config<'static> {
    Config {
        zid: &[7; 8],
        lease_ms: LEASE_MS,
        initial_sn: FIRST_SN,
        cookie,
    }
}

/// A listener that holds `cells` messages of heap, joined to a connector, with its owner subscribed.
struct Rig {
    a: Link2,
    b: Link2,
    ha: LinkHandle,
    hb: LinkHandle,
    to_b: Rc<RefCell<Pipe>>,
    heap: Vec<u8>,
}

fn params() -> Params {
    Params {
        // A lease of 8 s makes a keep-alive due 2 s after the last batch the link sent.
        ..Params::from_limits(&HEAP)
    }
}

fn rig(cells: usize) -> Rig {
    let to_b = Rc::new(RefCell::new(Pipe::default()));
    let to_a = Rc::new(RefCell::new(Pipe::default()));
    let a = Link2::with_lanes(
        Scripted {
            rx: to_a.clone(),
            tx: to_b.clone(),
        },
        Role::Connector,
        &config(b""),
        params(),
        2,
        1,
    )
    .expect("connector");
    let b = Link2::with_lanes(
        Scripted {
            rx: to_b.clone(),
            tx: to_a,
        },
        Role::Listener,
        &config(&[9; 8]),
        params(),
        2,
        1,
    )
    .expect("listener");
    let (ha, hb) = (a.handle(), b.handle());
    let message = params().message_limit;
    let mut rig = Rig {
        a,
        b,
        ha,
        hb,
        to_b,
        heap: std::vec![0; cells * message],
    };
    rig.a.open(rig.ha, 0).expect("open");
    rig.settle(0);
    assert!(rig.a.is_open() && rig.b.is_open(), "handshake");
    assert!(rig.b.session().lanes(), "both ends offered the lanes");
    rig.b
        .declare_subscriber(rig.hb, 1, codec::KEY)
        .expect("declare");
    rig.settle(1);
    while rig.a.next_notice().is_some() {}
    while rig.b.next_notice().is_some() {}
    rig
}

impl Rig {
    /// Pumps both ends until neither moves a byte or reads a batch.
    fn settle(&mut self, now: u64) {
        for _ in 0..200 {
            let a = self.a.pump(self.ha, now).expect("a pump");
            let b = self
                .b
                .pump_with(self.hb, now, &mut self.heap)
                .expect("b pump");
            if a.batches + b.batches + a.sent_bytes + b.sent_bytes == 0
                && !self.a.send_pending()
                && !self.b.send_pending()
            {
                return;
            }
        }
        panic!("the pair did not settle");
    }

    /// Puts one batch body on the stream `b` reads and pumps `b` until it has read it or cannot.
    fn feed(&mut self, body: &[u8], now: u64) -> Result<(), Error> {
        {
            let mut pipe = self.to_b.borrow_mut();
            pipe.bytes.extend((body.len() as u16).to_le_bytes());
            pipe.bytes.extend(body.iter());
        }
        self.pump_b(now)
    }

    fn pump_b(&mut self, now: u64) -> Result<(), Error> {
        for _ in 0..16 {
            let report = self.b.pump_with(self.hb, now, &mut self.heap)?;
            if report.batches == 0 && !self.b.send_pending() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// The payload of the next stored sample, read from the heap, and where it starts.
    fn take(&mut self) -> Option<(Vec<u8>, usize)> {
        loop {
            match self.b.next_notice()? {
                Notice::SampleStored(sample) => {
                    return Some((sample.payload(&self.heap).to_vec(), sample.start));
                }
                _ => continue,
            }
        }
    }
}

/// A payload of `size` bytes that differs from every other `index`.
fn payload(size: usize, index: usize) -> Vec<u8> {
    (0..size)
        .map(|i| ((i * 7 + 1 + index * 13) % 251) as u8)
        .collect()
}

fn leb(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The fragments of one Put on a lane, as the batch bodies a peer would send.
fn fragments(
    reliable: bool,
    priority: u8,
    first_sn: u32,
    size: usize,
    index: usize,
) -> Vec<Vec<u8>> {
    let mut message = std::vec![0x7du8, 0x00, 0x81, 0x01];
    message.extend_from_slice(codec::KEY.as_bytes());
    message.extend_from_slice(&[0x01 | 0x80, 0x43, 33]);
    message.extend_from_slice(&(index as i64).to_le_bytes());
    message.extend_from_slice(&(1000 + index as i64).to_le_bytes());
    message.push(16);
    message.extend_from_slice(&codec::GID);
    message.push((size & 0x7f) as u8 | 0x80);
    message.push((size >> 7) as u8);
    message.extend(payload(size, index));
    let mut out = Vec::new();
    let mut at = 0;
    let mut sn = first_sn;
    while at < message.len() {
        let end = (at + PIECE).min(message.len());
        let more = end < message.len();
        let flags = 0x06
            | if reliable { 0x20 } else { 0 }
            | if more { 0x40 } else { 0 }
            | if priority == 5 { 0 } else { 0x80 };
        let mut body = std::vec![flags];
        leb(&mut body, sn);
        if priority != 5 {
            body.extend_from_slice(&[0x31, priority]);
        }
        body.extend_from_slice(&message[at..end]);
        out.push(body);
        at = end;
        sn += 1;
    }
    out
}

#[test]
fn a_link_refuses_a_run_count_that_is_not_the_one_its_type_declares() {
    let build = |runs| {
        Link2::with_lanes(
            Scripted {
                rx: Rc::default(),
                tx: Rc::default(),
            },
            Role::Listener,
            &config(&[9; 8]),
            params(),
            runs,
            1,
        )
        .err()
    };
    for runs in [0, 1, 3] {
        assert_eq!(build(runs), Some(SessionError::InvalidConfig), "{runs}");
    }
    assert_eq!(build(2), None);
}

#[test]
fn two_lanes_interleave_into_two_cells_of_one_heap() {
    let mut rig = rig(4);
    let first = fragments(true, 2, FIRST_SN, 3000, 1);
    let second = fragments(true, 6, FIRST_SN, 3000, 2);
    assert_eq!(first.len(), second.len());
    for (at, (one, two)) in first.iter().zip(&second).enumerate() {
        rig.feed(one, 10 + at as u64).expect("first lane");
        rig.feed(two, 10 + at as u64).expect("second lane");
    }
    let (a, a_start) = rig.take().expect("first sample");
    let (b, b_start) = rig.take().expect("second sample");
    assert_eq!(a, payload(3000, 1));
    assert_eq!(b, payload(3000, 2));
    assert_ne!(a_start, b_start, "each run joined into a cell of its own");
}

#[test]
fn a_run_out_of_order_keeps_its_cell_while_the_other_samples_wait_unread() {
    // Three cells: one run stays open while two other messages complete and wait for the owner.
    let mut rig = rig(3);
    let slow = fragments(true, 2, FIRST_SN, 3000, 1);
    rig.feed(&slow[0], 10).expect("slow lane opens");
    for (index, sn) in [(2usize, FIRST_SN), (3, FIRST_SN)] {
        let lane = if index == 2 { 3 } else { 4 };
        for part in fragments(true, lane, sn, 3000, index) {
            rig.feed(&part, 11).expect("complete message");
        }
    }
    assert_eq!(rig.b.notices_queued(), 2, "two samples wait for the owner");
    // Every cell is taken: one by the open run and two by the stored samples. A fourth run waits.
    let waiting = fragments(true, 5, FIRST_SN, 3000, 4);
    rig.feed(&waiting[0], 12)
        .expect("it waits, it is not refused");
    assert_eq!(rig.b.notices_queued(), 2);
    assert!(
        rig.b
            .session()
            .run_slot(crate::zenoh_profile0::lane::Lane::DEFAULT)
            .is_some(),
        "the session still has a run for the fourth lane"
    );
    // The open run was not overwritten, and finishes intact.
    let (one, _) = rig.take().expect("first stored");
    assert_eq!(one, payload(3000, 2));
    rig.pump_b(13).expect("the waiting batch is read");
    for part in &slow[1..] {
        rig.feed(part, 14).expect("slow lane continues");
    }
    let mut seen = Vec::new();
    while let Some((bytes, _)) = rig.take() {
        seen.push(bytes);
    }
    assert!(seen.contains(&payload(3000, 3)));
    assert!(
        seen.contains(&payload(3000, 1)),
        "the slow run joined intact"
    );
}

#[test]
fn a_tick_that_writes_a_keep_alive_and_drops_a_late_best_effort_run_keeps_the_link_open() {
    let mut rig = rig(4);
    let parts = fragments(false, 2, FIRST_SN, 3000, 1);
    rig.feed(&parts[0], 1000).expect("the run opens");
    assert!(rig.b.session().reassembling());
    // At 6001 the run is late and a keep-alive has been due since 2000.
    rig.b.pump_with(rig.hb, 6001, &mut rig.heap).expect("tick");
    assert!(!rig.b.session().reassembling(), "the run was dropped");
    assert!(rig.b.is_open(), "a drop does not end the link");
    assert!(!rig.b.is_closed());
}

#[test]
fn a_new_message_never_takes_the_cell_of_a_sample_the_owner_has_not_read() {
    // Three cells. One run stays open while others complete out of order and the owner reads from the middle.
    let mut rig = rig(3);
    let size = 3000;
    let a = fragments(true, 2, FIRST_SN, size, 1);
    let pieces = a.len() as u32;
    rig.feed(&a[0], 10).expect("a opens in cell 0");
    for part in fragments(true, 3, FIRST_SN, size, 2) {
        rig.feed(&part, 11).expect("b completes in cell 1");
    }
    for part in fragments(true, 4, FIRST_SN, size, 3) {
        rig.feed(&part, 12).expect("c completes in cell 2");
    }
    let (b, _) = rig.take().expect("b is read first, which frees cell 1");
    assert_eq!(b, payload(size, 2));
    for part in fragments(true, 3, FIRST_SN + pieces, size, 4) {
        rig.feed(&part, 13).expect("d takes the freed cell 1");
    }
    for part in &a[1..] {
        rig.feed(part, 14).expect("a completes in cell 0");
    }
    // The queue holds c in cell 2, d in cell 1 and a in cell 0, so every cell is taken. Reading c frees cell 2,
    // and the search for a cell starts after cell 0, at cell 1, which holds d.
    let (c, _) = rig.take().expect("c");
    assert_eq!(c, payload(size, 3));
    for part in fragments(true, 4, FIRST_SN + pieces, size, 5) {
        rig.feed(&part, 15)
            .expect("e must find cell 2, not overwrite d");
    }
    let mut seen = Vec::new();
    while let Some((bytes, _)) = rig.take() {
        seen.push(bytes);
    }
    assert_eq!(seen.len(), 3);
    for index in [4usize, 1, 5] {
        assert!(
            seen.contains(&payload(size, index)),
            "message {index} is intact"
        );
    }
}

/// Prints the lanes exam: the lines `scripts/lib/zenoh_lanes_exam.py` judges.
#[test]
fn the_lanes_exam() {
    exam::run();
}
