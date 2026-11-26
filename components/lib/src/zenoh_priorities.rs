//! The priorities exam: a Profile 0 link sends each publication on the lane of its priority, and drains a queue
//! the lowest priority number first.
//!
//! A connector and a listener are joined through a scripted stream, once with the QoS unit extension offered by
//! both and once without. The exam queues publications in a `PriorityQueue`, drains them into the link, and reads
//! each frame the link queued back through the lane decoder. It prints one `[zenoh-exam] priorities ...` line for
//! each scenario, frame, drain order, count and refusal. `scripts/check/check-zenoh-profile0.py --slice priorities`
//! owns what those lines must be, and `scripts/lib/zenoh_priorities_exam.py` the bytes, the orders and the classes.

use crate::zenoh_link::{ByteLink, Error, LinkError, LinkHandle, LinkOf, Published};
use crate::zenoh_profile0::lane::{Lane, decode_lane_frame};
use crate::zenoh_profile0::priority_queue::{PriorityQueue, PushError};
use crate::zenoh_profile0::session::{Config, MAX_EVENTS, Params, Role, SessionError};
use crate::zenoh_profile0::{
    Bounds, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, Network, Qos, STREAM_LENGTH_BYTES,
    encode, frame_of,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
const PAYLOAD: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
/// The number the connector's OPEN announces: every lane it sends counts from it.
const FIRST_SN: u32 = 9000;
const FRAMED: usize = STREAM_LENGTH_BYTES + MAX_BATCH_BYTES;
const NOTICES: usize = 2 * MAX_EVENTS;
/// Publications each priority of the exam's queue holds.
const DEPTH: usize = 2;

type Node<const R: usize> =
    LinkOf<Scripted, FRAMED, 1, 2, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, NOTICES, MAX_EVENTS, R>;
type Queue = PriorityQueue<DEPTH, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES>;

fn line(kind: &str, text: &str) {
    println!("[zenoh-exam] priorities {kind} {text}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The attachment of a publication: its sequence number tells the publications apart.
fn attachment(sequence: i64) -> [u8; 33] {
    encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment")
}

fn qos(priority: u8, block: bool, express: bool) -> Qos {
    Qos::new(priority, block, express).expect("qos")
}

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

/// One end of a scripted stream: it reads `rx` and writes `tx`.
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

fn config(zid: &[u8], cookie: &[u8], initial_sn: u32) -> Config<'static> {
    Config {
        zid: Vec::leak(zid.to_vec()),
        lease_ms: 600_000,
        initial_sn,
        cookie: Vec::leak(cookie.to_vec()),
    }
}

/// A connector that publishes and a listener that declared the demo key, both open. `R` is the runs each holds: 2
/// makes both offer the QoS unit extension, so the pair has lanes, and 1 makes a pair without.
struct Rig<const R: usize> {
    ours: Node<R>,
    handle: LinkHandle,
    peer: Node<R>,
    peer_handle: LinkHandle,
    now: u64,
}

impl<const R: usize> Rig<R> {
    fn new() -> Self {
        let to_peer = Rc::new(RefCell::new(Pipe::default()));
        let to_ours = Rc::new(RefCell::new(Pipe::default()));
        let ours = Node::<R>::with_lanes(
            Scripted {
                rx: to_ours.clone(),
                tx: to_peer.clone(),
            },
            Role::Connector,
            &config(&[0xa1, 0xa2], b"", FIRST_SN),
            Params::DEMO,
            R,
            1,
        )
        .expect("connector");
        let peer = Node::<R>::with_lanes(
            Scripted {
                rx: to_peer,
                tx: to_ours,
            },
            Role::Listener,
            &config(&[0xb1, 0xb2], b"cookie-b", 100),
            Params::DEMO,
            R,
            1,
        )
        .expect("listener");
        let (handle, peer_handle) = (ours.handle(), peer.handle());
        let mut rig = Self {
            ours,
            handle,
            peer,
            peer_handle,
            now: 0,
        };
        rig.ours.open(rig.handle, 0).expect("open");
        rig.settle();
        assert!(rig.ours.is_open() && rig.peer.is_open(), "handshake");
        assert_eq!(rig.ours.session().lanes(), R >= 2);
        rig.peer
            .declare_subscriber(rig.peer_handle, 1, KEY)
            .expect("declare");
        rig.settle();
        assert_eq!(rig.ours.session().peer_subscriber_key(), Some(KEY));
        rig
    }

    /// Pumps both ends until neither moves a byte or reads a batch, and takes the notices the listener raised.
    fn settle(&mut self) {
        for _ in 0..400 {
            self.now += 1;
            let a = self.ours.pump(self.handle, self.now).expect("our pump");
            let b = self
                .peer
                .pump(self.peer_handle, self.now)
                .expect("peer pump");
            while self.peer.next_notice().is_some() {}
            while self.ours.next_notice().is_some() {}
            let quiet = a.batches + b.batches + a.sent_bytes + b.sent_bytes == 0
                && !self.ours.send_pending()
                && !self.peer.send_pending();
            if quiet {
                return;
            }
        }
        panic!("the pair did not settle");
    }

    fn drain(&mut self, queue: &mut Queue) -> Result<Option<u8>, Error> {
        let handle = self.handle;
        self.ours.drain(handle, queue)
    }
}

/// What the link queued last, read back through the lane decoder: the lane, the sequence number, the attachment
/// sequence and the QoS of its one PUSH, and its bytes.
fn last_frame<const R: usize>(link: &Node<R>) -> (Lane, u32, i64, Qos, Vec<u8>) {
    let batch = link.last_sent_batch();
    let header = decode_lane_frame(batch).expect("the last queued batch is a frame");
    let frame = frame_of(header.sn, header.body, &Bounds::DEMO, false).expect("the frame's body");
    let mut messages = frame.messages();
    let Some(Network::PushPut {
        qos, attachment, ..
    }) = messages.next()
    else {
        panic!("the last queued batch is not a push");
    };
    assert!(messages.next().is_none(), "one message in each FRAME");
    (
        header.lane,
        header.sn,
        attachment.sequence,
        qos,
        batch.to_vec(),
    )
}

/// Queues one publication, drains it and checks the frame it became: it is on the lane `lane`, carries the number
/// `sn`, the attachment sequence `sequence` and the QoS it was published with. The frame is then flushed.
fn send_frame<const R: usize>(
    rig: &mut Rig<R>,
    name: &str,
    lane: u8,
    sn: u32,
    sequence: i64,
    stated: Qos,
) {
    let mut queue = Queue::new();
    assert_eq!(
        queue.push(KEY, &attachment(sequence), &PAYLOAD, stated),
        Ok(Published::Queued)
    );
    assert_eq!(rig.drain(&mut queue), Ok(Some(stated.priority())));
    assert!(queue.is_empty());
    let (found, number, seen, qos, bytes) = last_frame(&rig.ours);
    assert_eq!(
        found,
        Lane {
            priority: lane,
            reliable: true
        },
        "{name}"
    );
    assert_eq!((number, seen, qos), (sn, sequence, stated), "{name}");
    line("frame", &format!("{name} {lane} {sn} {}", hex(&bytes)));
    rig.settle();
}

/// Drains `queue` until it is empty and returns the attachment sequences in the order they left.
fn drain_all<const R: usize>(rig: &mut Rig<R>, queue: &mut Queue) -> Vec<i64> {
    let mut order = Vec::new();
    while !queue.is_empty() {
        rig.drain(queue)
            .expect("drain")
            .expect("a publication left");
        order.push(last_frame(&rig.ours).2);
        rig.settle();
    }
    order
}

fn order_text(order: &[i64]) -> String {
    order
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn class(error: Error) -> &'static str {
    match error {
        Error::SendBusy => "send-busy",
        Error::SendAfterClose => "send-after-close",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

fn push_class(error: PushError) -> &'static str {
    match error {
        PushError::QueueFull => "queue-full",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

/// A publication refused because the link is not open yet stays queued, and leaves once the handshake is done.
#[test]
fn a_publication_refused_for_the_link_state_stays_queued() {
    let io = Scripted {
        rx: Rc::new(RefCell::new(Pipe::default())),
        tx: Rc::new(RefCell::new(Pipe::default())),
    };
    let mut link = Node::<2>::with_lanes(
        io,
        Role::Connector,
        &config(&[0xa1, 0xa2], b"", FIRST_SN),
        Params::DEMO,
        2,
        1,
    )
    .expect("connector");
    let handle = link.handle();
    link.open(handle, 0).expect("open");
    let mut queue = Queue::new();
    queue
        .push(KEY, &attachment(1), &PAYLOAD, qos(2, true, false))
        .expect("queued");
    // The INIT_SYN holds the slot, so the first refusal is the busy slot.
    assert_eq!(link.drain(handle, &mut queue), Err(Error::SendBusy));
    assert_eq!(queue.len(), 1);
    // Once it is flushed the slot is free and the link is still not open, so the refusal is the state.
    link.pump(handle, 1).expect("pump");
    assert!(!link.send_pending() && !link.is_open());
    let refused = link.drain(handle, &mut queue).expect_err("not open");
    assert!(matches!(
        refused,
        Error::Session(SessionError::NotOpen | SessionError::UndeclaredKey)
    ));
    assert_eq!(queue.len(), 1, "the publication waits for the link");
}

#[test]
fn the_priorities_exam() {
    // One: on a link that negotiated lanes each publication is a FRAME of the lane of its priority. Priority 5 has
    // no extension, any other the mandatory one, and each lane counts from the number the connector's OPEN gave.
    let mut rig = Rig::<2>::new();
    send_frame(&mut rig, "lane-0", 0, FIRST_SN, 1, qos(0, false, false));
    send_frame(
        &mut rig,
        "lane-2-first",
        2,
        FIRST_SN,
        1,
        qos(2, false, false),
    );
    line("ok", "lanes-write-the-priority");
    send_frame(
        &mut rig,
        "lane-2-second",
        2,
        FIRST_SN + 1,
        1,
        qos(2, true, false),
    );
    send_frame(&mut rig, "lane-5", 5, FIRST_SN, 1, qos(5, false, false));
    send_frame(
        &mut rig,
        "lane-7-express",
        7,
        FIRST_SN,
        1,
        qos(7, false, true),
    );
    let listener = rig.peer.session();
    let next = |priority| {
        listener.lane_next(Lane {
            priority,
            reliable: true,
        })
    };
    assert_eq!(
        (next(0), next(2), next(5), next(7)),
        (FIRST_SN + 1, FIRST_SN + 2, FIRST_SN + 1, FIRST_SN + 1),
        "the listener took every frame on the lane it was sent on"
    );
    line("ok", "each-lane-counts-its-own-numbers");

    // Two: without the extension every frame is on the default lane whatever its priority, and numbered in turn.
    let mut single = Rig::<1>::new();
    send_frame(
        &mut single,
        "single-p2",
        5,
        FIRST_SN,
        1,
        qos(2, false, false),
    );
    send_frame(
        &mut single,
        "single-p7",
        5,
        FIRST_SN + 1,
        1,
        qos(7, false, false),
    );
    line("ok", "a-link-without-lanes-keeps-one-counter");
    line("ok", "express-is-its-own-frame");

    // Three: five publications queued in the order 5, 2, 2, 0, 7 leave the lowest number first, and a priority
    // keeps its queue order.
    let mut rig = Rig::<2>::new();
    let mut queue = Queue::new();
    for (id, priority) in [(1, 5), (2, 2), (3, 2), (4, 0), (5, 7)] {
        assert_eq!(
            queue.push(KEY, &attachment(id), &PAYLOAD, qos(priority, false, false)),
            Ok(Published::Queued)
        );
    }
    let order = drain_all(&mut rig, &mut queue);
    assert_eq!(order, [4, 2, 3, 1, 5]);
    line("order", &format!("drain-order {}", order_text(&order)));
    line("ok", "drain-takes-the-highest-priority-first");
    line("ok", "drain-keeps-first-in-first-out-within-a-priority");

    // Four: a link without lanes numbers the frames in the order they leave, not the order they were queued.
    let mut single = Rig::<1>::new();
    let mut queue = Queue::new();
    for (id, priority) in [(11, 7), (12, 0)] {
        assert_eq!(
            queue.push(KEY, &attachment(id), &PAYLOAD, qos(priority, false, false)),
            Ok(Published::Queued)
        );
    }
    let mut order = Vec::new();
    for (name, sn) in [
        ("queued-p0-first", FIRST_SN),
        ("queued-p7-second", FIRST_SN + 1),
    ] {
        single
            .drain(&mut queue)
            .expect("drain")
            .expect("a publication left");
        let (lane, number, id, _, bytes) = last_frame(&single.ours);
        assert_eq!((lane, number), (Lane::DEFAULT, sn), "{name}");
        order.push(id);
        line("frame", &format!("{name} 5 {sn} {}", hex(&bytes)));
        single.settle();
    }
    assert_eq!(order, [12, 11]);
    line(
        "order",
        &format!("no-lanes-drain-order {}", order_text(&order)),
    );
    line("ok", "sequence-numbers-follow-the-drain-order");

    // Five: a full ring discards a Drop publication and counts it, and refuses a Block one. Another priority with
    // room still takes its publication.
    let mut queue = Queue::new();
    let drop3 = qos(3, false, false);
    for id in 1..=DEPTH as i64 {
        assert_eq!(
            queue.push(KEY, &attachment(id), &PAYLOAD, drop3),
            Ok(Published::Queued)
        );
    }
    assert_eq!(
        queue.push(KEY, &attachment(9), &PAYLOAD, drop3),
        Ok(Published::Dropped)
    );
    line(
        "count",
        &format!("queue-drops-after-a-full-drop {}", queue.dropped()),
    );
    let refused = queue
        .push(KEY, &attachment(9), &PAYLOAD, qos(3, true, false))
        .expect_err("a full ring refuses Block");
    assert_eq!(queue.len(), DEPTH);
    line(
        "count",
        &format!("queue-drops-after-a-full-block {}", queue.dropped()),
    );
    line(
        "refused",
        &format!("block-on-a-full-queue {}", push_class(refused)),
    );
    line("ok", "a-full-queue-drops-or-refuses");
    assert_eq!(
        queue.push(KEY, &attachment(10), &PAYLOAD, qos(6, false, false)),
        Ok(Published::Queued)
    );
    assert_eq!(queue.len(), DEPTH + 1);
    line("ok", "a-full-queue-leaves-other-priorities-open");

    // Six: drain writes one publication and stops. With the slot busy it writes nothing and the publication stays
    // queued, and once the slot is free it writes again.
    let mut rig = Rig::<2>::new();
    let mut queue = Queue::new();
    for id in 1..=2 {
        queue
            .push(KEY, &attachment(id), &PAYLOAD, qos(4, false, false))
            .expect("queued");
    }
    assert_eq!(rig.drain(&mut queue), Ok(Some(4)));
    assert_eq!(queue.len(), 1, "drain wrote one and stopped");
    let written = rig.ours.last_sent_batch().to_vec();
    let busy = rig.drain(&mut queue).expect_err("the slot is busy");
    assert_eq!(queue.len(), 1, "a refused drain keeps the publication");
    assert_eq!(rig.ours.last_sent_batch(), &written[..]);
    line("refused", &format!("drain-on-a-busy-slot {}", class(busy)));
    rig.settle();
    assert_eq!(rig.drain(&mut queue), Ok(Some(4)));
    assert!(queue.is_empty());
    rig.settle();
    assert_eq!(rig.drain(&mut queue), Ok(None), "nothing left to drain");
    line("ok", "drain-stops-at-a-busy-slot");

    rig.settle();
    let handle = rig.handle;
    rig.ours.close(handle, 0).expect("close");
    let error = rig
        .drain(&mut queue)
        .expect_err("a closed link refuses a drain");
    line("refused", &format!("drain-after-close {}", class(error)));
}
