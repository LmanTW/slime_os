//! The congestion exam: a Profile 0 link acts on the congestion control of a publication.
//!
//! `Link::publish_qos` discards a Drop publication and counts it when the send slot is busy, and refuses a Block
//! one as `SendBusy`. A frame stays in the send slot from the moment it is queued until the next pump flushes it,
//! so the exam publishes, then publishes again before it pumps. It prints one `[zenoh-exam] congestion ...` line
//! for each scenario, frame, count and refusal. `scripts/check/check-zenoh-profile0.py --slice congestion` owns
//! what those lines must be, and `scripts/lib/zenoh_congestion_exam.py` the bytes, the counts and the classes.

use crate::zenoh_link::{ByteLink, Error, Link, LinkError, LinkHandle, MAX_RETRIES, Published};
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::session::{Config, Role};
use crate::zenoh_profile0::{Message, Network, Qos, decode_batch};
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
/// The initial sequence number of the connector: the first FRAME it sends carries it, because the handshake and the
/// peer's declaration are not FRAMEs of its own.
const FIRST_SN: u32 = 9000;

fn line(kind: &str, text: &str) {
    println!("[zenoh-exam] congestion {kind} {text}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The attachment of every publication: the exam compares frames with the host reference, so they share one.
fn attachment() -> [u8; 33] {
    encode::attachment(1, 1000, &GID).expect("attachment")
}

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

/// One end of a scripted stream: it reads `rx` and writes `tx`, and takes at most `budget` more bytes when the
/// budget is set.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    tx: Rc<RefCell<Pipe>>,
    budget: Rc<RefCell<Option<usize>>>,
    /// How many sends of a non-empty buffer the stream took none of: the link's stall count, seen from outside.
    stalled: Rc<RefCell<u32>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let left = *self.budget.borrow();
        let take = left.map_or(buf.len(), |left| left.min(buf.len()));
        if take == 0 && !buf.is_empty() {
            *self.stalled.borrow_mut() += 1;
        }
        if let Some(left) = left {
            *self.budget.borrow_mut() = Some(left - take);
        }
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

fn config(zid: &[u8], cookie: &[u8], initial_sn: u32) -> Config<'static> {
    Config {
        zid: Vec::leak(zid.to_vec()),
        lease_ms: 600_000,
        initial_sn,
        cookie: Vec::leak(cookie.to_vec()),
    }
}

/// A connector that publishes and a listener that declared the demo key, both open.
struct Rig {
    ours: Link<Scripted>,
    handle: LinkHandle,
    peer: Link<Scripted>,
    peer_handle: LinkHandle,
    /// How many bytes the connector may still write; `None` is no limit.
    budget: Rc<RefCell<Option<usize>>>,
    /// The sends the connector's stream took nothing of.
    stalled: Rc<RefCell<u32>>,
}

impl Rig {
    fn new() -> Self {
        let to_peer = Rc::new(RefCell::new(Pipe::default()));
        let to_ours = Rc::new(RefCell::new(Pipe::default()));
        let budget = Rc::new(RefCell::new(None));
        let stalled = Rc::new(RefCell::new(0));
        let ours_io = Scripted {
            rx: to_ours.clone(),
            tx: to_peer.clone(),
            budget: budget.clone(),
            stalled: stalled.clone(),
        };
        let peer_io = Scripted {
            rx: to_peer,
            tx: to_ours,
            budget: Rc::new(RefCell::new(None)),
            stalled: Rc::new(RefCell::new(0)),
        };
        let ours = Link::new(
            ours_io,
            Role::Connector,
            &config(&[0xa1, 0xa2], b"", FIRST_SN),
            1,
        )
        .expect("connector");
        let peer = Link::new(
            peer_io,
            Role::Listener,
            &config(&[0xb1, 0xb2], b"cookie-b", 100),
            1,
        )
        .expect("listener");
        let (handle, peer_handle) = (ours.handle(), peer.handle());
        let mut rig = Self {
            ours,
            handle,
            peer,
            peer_handle,
            budget,
            stalled,
        };
        rig.ours.open(rig.handle, 0).expect("open");
        rig.settle(0);
        assert!(rig.ours.is_open() && rig.peer.is_open(), "handshake");
        // The listener declares the demo key, so the connector may publish on it.
        rig.peer
            .declare_subscriber(rig.peer_handle, 1, KEY)
            .expect("declare");
        rig.settle(1);
        assert_eq!(rig.ours.session().peer_subscriber_key(), Some(KEY));
        rig
    }

    /// Pumps both ends until neither moves a byte or reads a batch.
    fn settle(&mut self, now: u64) {
        for _ in 0..400 {
            let a = self.ours.pump(self.handle, now).expect("our pump");
            let b = self.peer.pump(self.peer_handle, now).expect("peer pump");
            let quiet = a.batches + b.batches + a.sent_bytes + b.sent_bytes == 0
                && !self.ours.send_pending()
                && !self.peer.send_pending();
            if quiet {
                return;
            }
        }
        panic!("the pair did not settle");
    }

    fn publish(&mut self, qos: Qos) -> Result<Published, Error> {
        let handle = self.handle;
        self.ours
            .publish_qos(handle, KEY, &attachment(), &PAYLOAD, qos)
    }
}

/// A Drop publication at the default priority: the PUSH default, which writes no extension.
fn drop_default() -> Qos {
    Qos::default()
}

/// A Block publication at priority 2.
fn block() -> Qos {
    Qos::new(2, true, false).expect("qos")
}

/// The sequence number and the QoS of the FRAME the link queued last.
fn last_frame(link: &Link<Scripted>) -> (u32, Qos) {
    let Ok(Message::Frame(frame)) = decode_batch(link.last_sent_batch()) else {
        panic!("the last queued batch is not a frame");
    };
    let Some(Network::PushPut { qos, .. }) = frame.messages().next() else {
        panic!("the last queued batch is not a push");
    };
    (frame.sn, qos)
}

fn count(label: &str, link: &Link<Scripted>) {
    line("count", &format!("{label} {}", link.dropped()));
}

fn class(error: Error) -> &'static str {
    match error {
        Error::SendBusy => "send-busy",
        Error::SendAfterClose => "send-after-close",
        Error::StaleHandle => "stale-handle",
        Error::RetryLimit => "retry-limit",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

#[test]
fn the_congestion_exam() {
    let mut rig = Rig::new();

    // One: with the slot free a publication is queued. It is the first FRAME the connector sends, so it carries
    // the initial sequence number, and with the default QoS it has no extension.
    assert!(!rig.ours.send_pending());
    assert_eq!(rig.publish(drop_default()), Ok(Published::Queued));
    assert_eq!(rig.ours.dropped(), 0);
    assert_eq!(last_frame(&rig.ours), (FIRST_SN, drop_default()));
    let first = rig.ours.last_sent_batch().to_vec();
    line("frame", &format!("first {FIRST_SN} {}", hex(&first)));
    line("ok", "drop-sends-when-the-slot-is-free");

    // Two: the frame still holds the slot, because nothing has pumped. A Drop publication is discarded, counted,
    // and queues nothing, so the slot still holds the first frame.
    assert!(rig.ours.send_pending());
    assert_eq!(rig.publish(drop_default()), Ok(Published::Dropped));
    assert_eq!(rig.ours.last_sent_batch(), &first[..]);
    count("after-one-drop", &rig.ours);
    line("ok", "drop-discards-when-the-slot-is-busy");

    // Three: further drops add to the count and still build no frame, so they spend no sequence number.
    assert_eq!(rig.publish(drop_default()), Ok(Published::Dropped));
    assert_eq!(rig.publish(drop_default()), Ok(Published::Dropped));
    assert_eq!(rig.ours.last_sent_batch(), &first[..]);
    count("after-three-drops", &rig.ours);
    line("ok", "drop-spends-no-sequence-number");

    // Four: a Block publication with the slot busy is refused as `SendBusy`, queues nothing and leaves the count.
    let error = rig.publish(block()).expect_err("a busy slot refuses Block");
    assert_eq!(error, Error::SendBusy);
    assert_eq!(rig.ours.last_sent_batch(), &first[..]);
    count("block-leaves-the-count", &rig.ours);
    line("refused", &format!("block-on-a-busy-slot {}", class(error)));
    line("ok", "block-keeps-send-busy");

    // Five: once the pump flushes the first frame, a Block publication is queued and carries the next sequence
    // number after it, which the three drops did not spend.
    rig.settle(2);
    assert!(!rig.ours.send_pending());
    assert_eq!(rig.publish(block()), Ok(Published::Queued));
    assert_eq!(last_frame(&rig.ours), (FIRST_SN + 1, block()));
    let after = rig.ours.last_sent_batch().to_vec();
    line(
        "frame",
        &format!("after-drops {} {}", FIRST_SN + 1, hex(&after)),
    );
    rig.settle(3);
    count("after-the-flush-and-a-send", &rig.ours);
    line("ok", "block-sends-after-the-flush");

    // Six: the count the owner reads is the three discards and nothing else.
    assert_eq!(rig.ours.dropped(), 3);
    line("ok", "dropped-count-is-reported");

    refusals();
}

/// The refusals `publish_qos` keeps from `publish`, and the retry limit.
fn refusals() {
    // A closed link refuses a publication, whatever its congestion control says.
    let mut rig = Rig::new();
    let handle = rig.handle;
    rig.ours.close(handle, 0).expect("close");
    let error = rig
        .publish(drop_default())
        .expect_err("a closed link refuses a publication");
    line("refused", &format!("drop-after-close {}", class(error)));

    // A handle of an earlier generation is refused.
    let rig = Rig::new();
    let mut newer = Link::new(
        Scripted {
            rx: Rc::new(RefCell::new(Pipe::default())),
            tx: Rc::new(RefCell::new(Pipe::default())),
            budget: Rc::new(RefCell::new(None)),
            stalled: Rc::new(RefCell::new(0)),
        },
        Role::Connector,
        &config(&[0xa1, 0xa2], b"", FIRST_SN),
        2,
    )
    .expect("a link of the next generation");
    let error = newer
        .publish_qos(rig.handle, KEY, &attachment(), &PAYLOAD, drop_default())
        .expect_err("a handle of generation 1 on a link of generation 2");
    line("refused", &format!("stale-handle {}", class(error)));

    // A peer that accepts nothing ends the link on the send after `MAX_RETRIES` stalled ones, which is the fourth.
    // A pump sends twice, so that falls inside the second pump. A Block publication refused between the pumps
    // leaves the stall count alone: one that reset it would let the link outlive the bound below, and one that
    // added to it would end the link on an earlier send.
    let mut rig = Rig::new();
    assert_eq!(rig.publish(drop_default()), Ok(Published::Queued));
    *rig.budget.borrow_mut() = Some(0);
    let handle = rig.handle;
    let mut pumps = 0u32;
    let reported = loop {
        pumps += 1;
        match rig.ours.pump(handle, 10 + u64::from(pumps)) {
            Ok(_) => assert_eq!(
                rig.publish(block()),
                Err(Error::SendBusy),
                "a Block publication between two pumps"
            ),
            Err(error) => break error,
        }
        assert!(
            pumps <= 2 * (MAX_RETRIES + 1),
            "the link never reached its limit"
        );
    };
    let stalled = *rig.stalled.borrow();
    assert_eq!(stalled, MAX_RETRIES + 1);
    line("count", &format!("retry-limit-on-pump {stalled}"));
    line(
        "refused",
        &format!("block-stalled-past-the-limit {}", class(reported)),
    );
}

/// A Drop publication before the handshake ends is refused as `NotOpen`, as it is with a free slot. The INIT_SYN
/// holds the send slot, so this is the busy path, and a count here would be a publication the free path refuses.
#[test]
fn a_drop_publication_before_open_is_refused_not_counted() {
    let io = Scripted {
        rx: Rc::new(RefCell::new(Pipe::default())),
        tx: Rc::new(RefCell::new(Pipe::default())),
        budget: Rc::new(RefCell::new(None)),
        stalled: Rc::new(RefCell::new(0)),
    };
    let mut link = Link::new(
        io,
        Role::Connector,
        &config(&[0xa1, 0xa2], b"", FIRST_SN),
        1,
    )
    .expect("connector")
    .with_client_role()
    .expect("client role");
    let handle = link.handle();
    link.open(handle, 0).expect("open");
    assert!(link.send_pending(), "the INIT_SYN holds the send slot");
    let error = link
        .publish_qos(handle, KEY, &attachment(), &PAYLOAD, drop_default())
        .expect_err("a link that is not open refuses a publication");
    assert_eq!(
        error,
        Error::Session(crate::zenoh_profile0::session::SessionError::NotOpen)
    );
    assert_eq!(link.dropped(), 0);
}
