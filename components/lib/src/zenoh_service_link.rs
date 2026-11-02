//! The service core over a link: the exam that prints the `[zenoh-exam] servicelink ...` lines.
//!
//! The core queues a declaration or a publication through the link's single send slot and delivers to its
//! rings only after the slot has been flushed. A frame handed to the byte stream just before the stream
//! resets may still reach the peer, so a holder can be told a publication failed that the peer received.
//! `scripts/check/check-zenoh-profile0.py --slice service-link` owns what these lines must be, and
//! `scripts/lib/zenoh_service_link_exam.py` the bytes, the order, the counts and the classes.

mod behaviour;
pub(crate) mod pair;

use crate::zenoh_link::{ByteLink, Error as LinkError, LinkHandle, LinkOf, Notice};
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::session::{Params, Role};
use crate::zenoh_service::exam::{Exam, GID, HOLDERS, KEYS, ROWS, hex, params, rows};
use crate::zenoh_service::{Item, OverLink, Peer, ServiceError, Settled};
use pair::{FailAfterSend, Far, Io, Pipe, Stalling, Svc, cfg, pair};
use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

/// The links of the exam: a 514-byte framed batch, one alias, five subscriptions, 129-byte keys, 12-byte
/// payloads and eight notices.
type Link<L> = LinkOf<L, 514, 1, 5, 129, 12, 8, 4>;
const NOTICES: usize = 8;

fn line(text: &str) {
    println!("[zenoh-exam] servicelink {text}");
}

fn payload(sequence: i64) -> [u8; 3] {
    [sequence as u8, 2, 3]
}

fn class(error: ServiceError) -> &'static str {
    match error {
        ServiceError::Busy => "busy",
        ServiceError::NotGranted => "not-granted",
        ServiceError::UnknownHolder => "unknown-holder",
        ServiceError::TooLarge => "too-large",
        ServiceError::Link(LinkError::SendAfterClose) => "link-closed",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

fn refused<T: core::fmt::Debug>(name: &str, outcome: Result<T, ServiceError>) {
    let error = outcome.expect_err(name);
    line(&format!("refused {name} {}", class(error)));
}

/// One round of both links.
fn step<A: ByteLink, B: ByteLink>(
    svc: &mut Link<A>,
    far: &mut Link<B>,
    hs: LinkHandle,
    hf: LinkHandle,
    now: &mut u64,
) {
    *now += 1;
    far.pump(hf, *now).expect("pump the peer");
    svc.pump(hs, *now).expect("pump the service");
}

/// Drains what a holder's ring holds, one line per sample.
fn deliver(phase: &str, core: &mut Exam<'_>, holder: usize) {
    while let Some(item) = core.take(holder).expect("a declared holder") {
        let Item::Sample(sample) = item else {
            panic!("an unexpected loss in {phase}")
        };
        line(&format!(
            "delivered {phase} {} {} {} {}",
            HOLDERS[holder],
            sample.subscription,
            sample.sequence,
            hex(sample.payload())
        ));
    }
}

fn held(label: &str, core: &Exam<'_>, holder: usize) {
    let (samples, lost) = core.held(holder).expect("a declared holder");
    line(&format!(
        "held {label} {} {samples} {lost}",
        HOLDERS[holder]
    ));
}

/// Declares every subscription through the link, one frame at a time, and prints the frames the peer took.
fn declare_all<'k, A: ByteLink, B: ByteLink>(
    core: &mut Exam<'k>,
    over: &mut OverLink<'k, 12>,
    svc: &mut Link<A>,
    far: &mut Link<B>,
    hs: LinkHandle,
    hf: LinkHandle,
    now: &mut u64,
    show: bool,
) {
    for id in 1..=2u16 {
        assert!(over.declare_next(core, svc, hs).expect("queues"));
        let frame = svc.last_sent_batch().to_vec();
        if show {
            line(&format!("declare {id} queued {}", core.declared()));
            refused("declare-while-one-waits", over.declare_next(core, svc, hs));
            if id == 1 {
                refused(
                    "publish-while-a-declaration-waits",
                    over.publish(core, svc, hs, 0, KEYS[0], 7, 1007, &payload(7)),
                );
            }
        }
        step(svc, far, hs, hf, now);
        if show {
            refused(
                "declare-after-the-flush-before-settle",
                over.declare_next(core, svc, hs),
            );
            if id == 1 {
                refused(
                    "publish-after-the-flush-of-a-declaration",
                    over.publish(core, svc, hs, 0, KEYS[0], 7, 1007, &payload(7)),
                );
            }
        }
        let settled = over.settle(core, svc).expect("settle");
        assert_eq!(settled, Settled::Declared { id });
        if show {
            line(&format!("declare {id} declared {}", core.declared()));
            line(&format!("frame declare-{id} {}", hex(&frame)));
        }
    }
    assert!(!over.declare_next(core, svc, hs).expect("nothing left"));
}

/// The peer declares `k1` and `k3`, so the service may send to them.
fn peer_declares<A: ByteLink, B: ByteLink>(
    svc: &mut Link<A>,
    far: &mut Link<B>,
    hs: LinkHandle,
    hf: LinkHandle,
    now: &mut u64,
) {
    for (id, key) in [(1u32, KEYS[0]), (2, KEYS[2])] {
        far.declare_subscriber(hf, id, key)
            .expect("the peer declares");
        for _ in 0..3 {
            step(svc, far, hs, hf, now);
        }
    }
    while svc.next_notice().is_some() {}
}

fn peer_puts<A: ByteLink, B: ByteLink>(
    far: &mut Link<B>,
    svc: &mut Link<A>,
    hs: LinkHandle,
    hf: LinkHandle,
    key: &str,
    sequence: i64,
    now: &mut u64,
) {
    let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
    far.publish(hf, key, &attachment, &payload(sequence))
        .expect("the peer queues");
    for _ in 0..3 {
        step(svc, far, hs, hf, now);
    }
}

fn the_exam() {
    let (mut svc, mut far, hs, hf) = pair();
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let mut over = OverLink::<12>::new();
    let mut now = 20u64;
    line(&format!("limits 3 4 12 3 {NOTICES}"));
    for (holder, key, publish, subscribe) in ROWS {
        line(&format!(
            "grant {} k{} {}{}",
            HOLDERS[holder],
            key + 1,
            if publish { 'p' } else { '-' },
            if subscribe { 's' } else { '-' }
        ));
    }
    let sizes = Exam::sizes();
    line(&format!("size slot {}", sizes.slot));
    line(&format!("size row {}", sizes.row));
    line(&format!("size holder {}", sizes.holder));
    line(&format!("size fixed {}", sizes.fixed));

    // One: the declarations go out one frame at a time. A second waits for the send slot.
    declare_all(
        &mut core, &mut over, &mut svc, &mut far, hs, hf, &mut now, true,
    );
    line("ok declaration-goes-one-frame-at-a-time");

    // Two: a publication before the peer declares its key reaches the local holders at once.
    let published = over
        .publish(&mut core, &mut svc, hs, 0, KEYS[0], 99, 1099, &payload(99))
        .expect("granted")
        .expect("delivered at once");
    assert_eq!(published.peer, Peer::NotSubscribed);
    line(&format!(
        "published a k1 not-subscribed {}",
        published.reached
    ));
    for holder in [0, 1] {
        deliver("before-the-peer-declares", &mut core, holder);
    }
    peer_declares(&mut svc, &mut far, hs, hf, &mut now);

    // Three: a publication the peer subscribed to waits for the flush, and a second one waits behind it.
    assert!(
        over.publish(
            &mut core,
            &mut svc,
            hs,
            0,
            KEYS[0],
            100,
            1100,
            &payload(100)
        )
        .expect("granted")
        .is_none()
    );
    let frame_a = svc.last_sent_batch().to_vec();
    line("published a k1 queued");
    held("before-the-flush", &core, 0);
    held("before-the-flush", &core, 1);
    refused(
        "publish-while-one-waits",
        over.publish(
            &mut core,
            &mut svc,
            hs,
            1,
            KEYS[2],
            101,
            1101,
            &payload(101),
        ),
    );
    refused(
        "declare-while-a-publication-waits",
        over.declare_next(&mut core, &mut svc, hs),
    );
    assert_eq!(
        over.settle(&mut core, &svc).expect("settle"),
        Settled::Waiting
    );
    step(&mut svc, &mut far, hs, hf, &mut now);
    refused(
        "publish-after-the-flush-before-settle",
        over.publish(
            &mut core,
            &mut svc,
            hs,
            1,
            KEYS[2],
            101,
            1101,
            &payload(101),
        ),
    );
    refused(
        "declare-after-the-flush-of-a-publication",
        over.declare_next(&mut core, &mut svc, hs),
    );
    let Settled::Published { reached } = over.settle(&mut core, &svc).expect("settle") else {
        panic!("the frame left")
    };
    line(&format!("settled publish-a {reached}"));
    line(&format!("frame publish-a {}", hex(&frame_a)));
    assert!(
        over.publish(
            &mut core,
            &mut svc,
            hs,
            1,
            KEYS[2],
            101,
            1101,
            &payload(101)
        )
        .expect("granted")
        .is_none()
    );
    let frame_b = svc.last_sent_batch().to_vec();
    line("published b k3 queued");
    step(&mut svc, &mut far, hs, hf, &mut now);
    let Settled::Published { reached } = over.settle(&mut core, &svc).expect("settle") else {
        panic!("the frame left")
    };
    line(&format!("settled publish-b {reached}"));
    line(&format!("frame publish-b {}", hex(&frame_b)));
    for holder in [0, 1] {
        deliver("after-the-flush", &mut core, holder);
    }
    line("ok a-publication-reaches-the-rings-after-the-flush");

    // Four: a refused publication reaches no ring and queues nothing.
    let before = (
        core.held(0).unwrap(),
        core.held(1).unwrap(),
        core.held(2).unwrap(),
        svc.send_pending(),
    );
    refused(
        "publish-without-a-publish-right",
        over.publish(&mut core, &mut svc, hs, 1, KEYS[0], 7, 1007, &payload(7)),
    );
    refused(
        "publish-to-a-key-with-no-row",
        over.publish(&mut core, &mut svc, hs, 2, KEYS[2], 7, 1007, &payload(7)),
    );
    refused(
        "publish-by-an-unknown-holder",
        over.publish(&mut core, &mut svc, hs, 3, KEYS[0], 7, 1007, &payload(7)),
    );
    refused(
        "publish-payload-over-the-sample-size",
        over.publish(&mut core, &mut svc, hs, 0, KEYS[0], 7, 1007, &[0u8; 13]),
    );
    assert_eq!(
        before,
        (
            core.held(0).unwrap(),
            core.held(1).unwrap(),
            core.held(2).unwrap(),
            svc.send_pending()
        )
    );
    line("ok a-refused-publication-reaches-no-one");

    // Five: a sample from the peer reaches the holders subscribed to the subscription that matched.
    peer_puts(&mut far, &mut svc, hs, hf, KEYS[0], 10, &mut now);
    peer_puts(&mut far, &mut svc, hs, hf, KEYS[1], 11, &mut now);
    let routed = core
        .drain_notices(&mut svc)
        .expect("the link of the core's parameters");
    line(&format!("routed {routed}"));
    for holder in [0, 1, 2] {
        deliver("from-the-peer", &mut core, holder);
    }
    line("ok a-sample-from-the-peer-is-routed-by-its-subscription");

    // Six: a burst the service does not drain waits in the notice queue and the stream, and the ring keeps the newest.
    let mut queued = 0;
    for sequence in 100..120i64 {
        let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
        if far
            .publish(hf, KEYS[0], &attachment, &payload(sequence))
            .is_ok()
        {
            queued += 1;
        }
        for _ in 0..2 {
            step(&mut svc, &mut far, hs, hf, &mut now);
        }
    }
    line(&format!("burst {queued} {}", svc.notices_queued()));
    core.drain_notices(&mut svc)
        .expect("the link of the core's parameters");
    for _ in 0..20 {
        step(&mut svc, &mut far, hs, hf, &mut now);
        core.drain_notices(&mut svc)
            .expect("the link of the core's parameters");
    }
    held("after-the-burst", &core, 0);
    line("ok a-burst-waits-in-the-stream-and-the-ring-counts-the-loss");

    keep_alive_slot();
    failing_stream();
}

/// A keep-alive that the link queued holds the send slot while the core has nothing pending. The core refuses a
/// declaration and a publication as busy and changes nothing, and works once the stream takes the keep-alive.
fn keep_alive_slot() {
    type Stalled = Link<Stalling>;
    let ab = Rc::new(RefCell::new(Pipe::default()));
    let ba = Rc::new(RefCell::new(Pipe::default()));
    let stall = Rc::new(RefCell::new(false));
    let peer_params = Params {
        local: 2,
        per_side: 3,
        ..params()
    };
    let mut svc = Stalled::with_params(
        Stalling {
            inner: Io {
                rx: ab.clone(),
                tx: ba.clone(),
            },
            stall: stall.clone(),
        },
        Role::Listener,
        &cfg(&[0xb2; 8], &[0xc0; 32], 7000),
        params(),
        1,
    )
    .expect("service");
    let mut far = Far::with_params(
        Io { rx: ba, tx: ab },
        Role::Connector,
        &cfg(&[0xa1; 8], b"", 9000),
        peer_params,
        1,
    )
    .expect("peer");
    let (hs, hf) = (svc.handle(), far.handle());
    far.open(hf, 0).expect("open");
    let mut now = 0u64;
    for _ in 0..12 {
        step(&mut svc, &mut far, hs, hf, &mut now);
        if svc.is_open() && far.is_open() {
            break;
        }
    }
    assert!(svc.is_open() && far.is_open());
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let mut over = OverLink::<12>::new();
    declare_all(
        &mut core, &mut over, &mut svc, &mut far, hs, hf, &mut now, false,
    );
    far.declare_subscriber(hf, 1, KEYS[0])
        .expect("the peer declares");
    for _ in 0..3 {
        step(&mut svc, &mut far, hs, hf, &mut now);
    }
    while svc.next_notice().is_some() {}
    assert!(!svc.send_pending());
    *stall.borrow_mut() = true;
    now += 3_000;
    svc.pump(hs, now)
        .expect("pump the service at the keep-alive deadline");
    assert!(
        svc.send_pending(),
        "the link queued a keep-alive that the stream did not take"
    );
    line("keep-alive queued");
    let held_before = (
        core.held(0).unwrap(),
        core.held(1).unwrap(),
        core.held(2).unwrap(),
    );
    refused(
        "publish-while-a-keep-alive-waits",
        over.publish(&mut core, &mut svc, hs, 0, KEYS[0], 8, 1008, &payload(8)),
    );
    refused(
        "declare-while-a-keep-alive-waits",
        over.declare_next(&mut core, &mut svc, hs),
    );
    assert_eq!(
        held_before,
        (
            core.held(0).unwrap(),
            core.held(1).unwrap(),
            core.held(2).unwrap()
        )
    );
    assert_eq!(over.settle(&mut core, &svc).expect("settle"), Settled::Idle);
    *stall.borrow_mut() = false;
    now += 1;
    svc.pump(hs, now)
        .expect("pump after the stream takes the keep-alive");
    assert!(!svc.send_pending());
    assert!(
        over.publish(&mut core, &mut svc, hs, 0, KEYS[0], 9, 1009, &payload(9))
            .expect("granted")
            .is_none()
    );
    line("published a k1 queued-after-the-keep-alive");
    line("ok a-keep-alive-holds-the-send-slot-and-the-core-says-busy");
}

/// A stream that accepts the frame and then resets: the local rings never took a copy, and the peer did.
fn failing_stream() {
    type Failing = Link<FailAfterSend>;
    let ab = Rc::new(RefCell::new(Pipe::default()));
    let ba = Rc::new(RefCell::new(Pipe::default()));
    let armed = Rc::new(RefCell::new(false));
    let peer_params = Params {
        local: 2,
        per_side: 3,
        ..params()
    };
    let mut svc = Failing::with_params(
        FailAfterSend {
            inner: Io {
                rx: ab.clone(),
                tx: ba.clone(),
            },
            armed: armed.clone(),
            sent_since_armed: false,
        },
        Role::Listener,
        &cfg(&[0xb2; 8], &[0xc0; 32], 7000),
        params(),
        1,
    )
    .expect("service");
    let mut far = Far::with_params(
        Io { rx: ba, tx: ab },
        Role::Connector,
        &cfg(&[0xa1; 8], b"", 9000),
        peer_params,
        1,
    )
    .expect("peer");
    let (hs, hf) = (svc.handle(), far.handle());
    far.open(hf, 0).expect("open");
    let mut now = 0u64;
    for _ in 0..12 {
        step(&mut svc, &mut far, hs, hf, &mut now);
        if svc.is_open() && far.is_open() {
            break;
        }
    }
    assert!(svc.is_open() && far.is_open());
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let mut over = OverLink::<12>::new();
    declare_all(
        &mut core, &mut over, &mut svc, &mut far, hs, hf, &mut now, false,
    );
    far.declare_subscriber(hf, 1, KEYS[0])
        .expect("the peer declares");
    for _ in 0..3 {
        step(&mut svc, &mut far, hs, hf, &mut now);
    }
    while svc.next_notice().is_some() {}
    *armed.borrow_mut() = true;
    assert!(
        over.publish(
            &mut core,
            &mut svc,
            hs,
            0,
            KEYS[0],
            100,
            1100,
            &payload(100)
        )
        .expect("granted")
        .is_none()
    );
    line("published a k1 queued-on-a-stream-that-will-reset");
    now += 1;
    let error = svc.pump(hs, now).expect_err("the stream resets");
    assert_eq!(error, LinkError::Link(crate::zenoh_link::LinkError::Reset));
    line("pump reset");
    refused("settle-after-reset", over.settle(&mut core, &svc));
    held("after-the-reset", &core, 0);
    held("after-the-reset", &core, 1);
    now += 1;
    far.pump(hf, now).ok();
    let mut received = 0;
    while let Some(notice) = far.next_notice() {
        if matches!(notice, Notice::SampleDelivered(_)) {
            received += 1;
        }
    }
    line(&format!("peer-received after-the-reset {received}"));
    line("ok a-frame-handed-over-before-a-reset-reaches-no-local-ring");
    let _: Option<(Svc, Vec<String>)> = None;
}

#[test]
fn the_service_link_exam() {
    the_exam();
}
