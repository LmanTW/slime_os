//! Host tests for a FRAME taken by its lane. The scenarios are the ones of `scripts/lib/zenoh_lanes_exam.py`
//! that concern a whole FRAME: a reliable lane takes exactly its next number, and a best-effort lane takes a
//! number ahead, counts the gap and drops one that is not ahead.

use super::*;
use crate::zenoh_profile0::encode::FrameEncoder;
use crate::zenoh_profile0::session::SessionOf;
use std::vec::Vec;

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const SN0: u32 = 7000;
const GID: [u8; 16] = [0xe0; 16];

/// The writes a lane FRAME needs: the body is one Put, framed by the exam's reference writer rules.
fn put_body(sequence: i64) -> Vec<u8> {
    let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    frame
        .push_put(Mapping::Sender, KEY, &attachment, &[1, 2, 3])
        .expect("put");
    let length = frame.finish().expect("finish");
    // The FRAME header is `25 00` for sequence 0, and the network messages follow it.
    out[2..length].to_vec()
}

fn lane_frame(reliable: bool, priority: u8, sn: u32, body: &[u8]) -> Vec<u8> {
    let mut batch = std::vec![0x05 | if reliable { 0x20 } else { 0 }];
    if priority != 5 {
        batch[0] |= 0x80;
    }
    let mut at = batch.len();
    batch.resize(at + 5, 0);
    let mut value = sn;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            batch[at] = byte;
            at += 1;
            break;
        }
        batch[at] = byte | 0x80;
        at += 1;
    }
    batch.truncate(at);
    if priority != 5 {
        batch.extend_from_slice(&[0x31, priority]);
    }
    batch.extend_from_slice(body);
    batch
}

/// A listener with 2 runs and a connector with 2 runs, both open with the QoS extension negotiated.
/// The connector declares the subscription, so the listener holds the peer's subscriber on `KEY`, and the
/// listener, the receiver of the frames under test, has its own subscription on `KEY`.
/// A session built for 2 runs: the two that a pair of the exam's lanes needs.
type Two = SessionOf<1, 2, MAX_KEY_BYTES, MAX_EVENTS, 2>;

fn open_pair() -> (Two, Two) {
    let mut a = Two::with_lanes(
        Role::Connector,
        &Config {
            zid: &[0xa1; 8],
            lease_ms: 2000,
            initial_sn: 100,
            cookie: &[],
        },
        Params::DEMO,
        2,
    )
    .expect("connector");
    let cookie = [0xc0u8; 8];
    let mut b = Two::with_lanes(
        Role::Listener,
        &Config {
            zid: &[0xb2; 8],
            lease_ms: 2000,
            initial_sn: SN0,
            cookie: &cookie,
        },
        Params::DEMO,
        2,
    )
    .expect("listener");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let init_syn = a
        .connect(0, &mut out)
        .expect("connect")
        .batch(&out)
        .to_vec();
    let init_ack = b
        .on_batch(&init_syn, 1, &mut out)
        .expect("init syn")
        .batch(&out)
        .to_vec();
    let open_syn = a
        .on_batch(&init_ack, 2, &mut out)
        .expect("init ack")
        .batch(&out)
        .to_vec();
    let open_ack = b
        .on_batch(&open_syn, 3, &mut out)
        .expect("open syn")
        .batch(&out)
        .to_vec();
    a.on_batch(&open_ack, 4, &mut out).expect("open ack");
    assert!(a.lanes() && b.lanes());
    // The connector announced initial number 100, so the listener counts every lane from it.
    (a, b)
}

/// The listener declares its subscription and the connector, the sender of the frames, learns of it.
fn subscribed() -> (Two, Two) {
    let (mut sender, mut receiver) = open_pair();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let declare = receiver
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("declare")
        .batch(&out)
        .to_vec();
    sender.on_batch(&declare, 5, &mut out).expect("learns");
    (sender, receiver)
}

fn feed<const R: usize>(
    session: &mut SessionOf<1, 2, MAX_KEY_BYTES, MAX_EVENTS, R>,
    batch: &[u8],
    now: u64,
) -> Result<Vec<std::string::String>, SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(batch, now, &mut out)?;
    Ok(outcome
        .events
        .iter()
        .map(|event| match *event {
            Event::SampleDelivered { sequence, .. } => std::format!("sample {sequence}"),
            Event::Dropped { priority, cause } => {
                std::format!("drop p{priority} {}", cause.name())
            }
            other => std::format!("{other:?}"),
        })
        .collect())
}

#[test]
fn a_reliable_lane_counts_from_the_number_the_open_announced() {
    let (_, mut receiver) = subscribed();
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        100
    );
    let body = put_body(1);
    // Two lanes take the same number, because each counts alone.
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 2, 100, &body), 6),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 7, 100, &body), 7),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 2, 101, &body), 8),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        102
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 7,
            reliable: true
        }),
        101
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 0,
            reliable: true
        }),
        100
    );
}

#[test]
fn a_reliable_lane_refuses_a_number_that_is_not_its_next() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 2, 101, &body), 6),
        Err(SessionError::SequenceMismatch)
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        100
    );
}

#[test]
fn the_default_lane_is_the_session_counter() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    assert_eq!(receiver.expected_rx_sn(), 100);
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 5, 100, &body), 6),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(receiver.expected_rx_sn(), 101);
    // The plain path and the lane path read one counter, so a plain FRAME follows a lane FRAME.
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 101);
}

#[test]
fn a_best_effort_lane_takes_a_gap_and_counts_past_it() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 100, &body), 6),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 103, &body), 7),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 5,
            reliable: false
        }),
        104
    );
    // A best-effort lane is its own lane: the reliable one on the same priority is untouched.
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 100);
}

#[test]
fn a_best_effort_lane_drops_a_number_that_is_not_ahead() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    let lane = Lane {
        priority: 5,
        reliable: false,
    };
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 100, &body), 6),
        Ok(std::vec!["sample 1".into()])
    );
    // The same number, then one behind it: both are stale, and the lane stays open.
    for (at, sn) in [(7, 100), (8, 99)] {
        assert_eq!(
            feed(&mut receiver, &lane_frame(false, 5, sn, &body), at),
            Ok(std::vec!["drop p5 stale-sequence".into()])
        );
    }
    assert_eq!(receiver.lane_next(lane), 101);
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 102, &body), 9),
        Ok(std::vec!["sample 1".into()])
    );
}

#[test]
fn a_best_effort_lane_takes_a_number_up_to_half_the_range_ahead() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    let lane = Lane {
        priority: 5,
        reliable: false,
    };
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 100, &body), 6),
        Ok(std::vec!["sample 1".into()])
    );
    let ahead = 101u32.wrapping_add((1 << 31) - 2);
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, ahead, &body), 7),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(receiver.lane_next(lane), ahead.wrapping_add(1));
    // One more than half the range ahead of the new count is behind it.
    let behind = ahead.wrapping_add(1).wrapping_add((1 << 31) - 1);
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, behind, &body), 8),
        Ok(std::vec!["drop p5 stale-sequence".into()])
    );
}

#[test]
fn a_best_effort_frame_that_fails_after_it_was_taken_is_dropped_and_counted_past() {
    let (_, mut receiver) = subscribed();
    let lane = Lane {
        priority: 5,
        reliable: false,
    };
    // A network message the decoder does not know.
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 100, &[0xff]), 6),
        Ok(std::vec!["drop p5 completed".into()])
    );
    assert_eq!(receiver.lane_next(lane), 101);
    // The same bytes on a reliable lane are refused, and the lane does not move.
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 5, 100, &[0xff]), 7),
        Err(SessionError::Decode(Refusal::UnsupportedMessage))
    );
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 100);
}

#[test]
fn a_priority_above_seven_is_refused() {
    let (_, mut receiver) = subscribed();
    let body = put_body(1);
    let mut bad = lane_frame(true, 5, 100, &body);
    bad[0] |= 0x80;
    bad.splice(2..2, [0x31, 8]);
    assert_eq!(
        feed(&mut receiver, &bad, 6),
        Err(SessionError::Decode(Refusal::UnsupportedExtension))
    );
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 100);
}

/// A pair that both hold one run, open with no extension negotiated.
fn one_run_pair() -> (Session, Session) {
    let mut a = Session::with_lanes(
        Role::Connector,
        &Config {
            zid: &[0xa1; 8],
            lease_ms: 2000,
            initial_sn: 100,
            cookie: &[],
        },
        Params::DEMO,
        1,
    )
    .expect("connector");
    let mut b = Session::with_lanes(
        Role::Listener,
        &Config {
            zid: &[0xb2; 8],
            lease_ms: 2000,
            initial_sn: SN0,
            cookie: &[0xc0; 8],
        },
        Params::DEMO,
        1,
    )
    .expect("listener");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let init_syn = a
        .connect(0, &mut out)
        .expect("connect")
        .batch(&out)
        .to_vec();
    let init_ack = b
        .on_batch(&init_syn, 1, &mut out)
        .expect("syn")
        .batch(&out)
        .to_vec();
    let open_syn = a
        .on_batch(&init_ack, 2, &mut out)
        .expect("ack")
        .batch(&out)
        .to_vec();
    let open_ack = b
        .on_batch(&open_syn, 3, &mut out)
        .expect("open")
        .batch(&out)
        .to_vec();
    a.on_batch(&open_ack, 4, &mut out).expect("open ack");
    let declare = b
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("declare")
        .batch(&out)
        .to_vec();
    a.on_batch(&declare, 5, &mut out).expect("learns");
    (a, b)
}

#[test]
fn a_session_with_one_run_refuses_a_priority_and_a_best_effort_frame_as_it_always_did() {
    let (_, mut receiver) = one_run_pair();
    assert!(!receiver.lanes());
    let body = put_body(1);
    // The extension flag on a FRAME, and the best-effort form: both were refused before lanes existed.
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 2, 100, &body), 6),
        Err(SessionError::Decode(Refusal::UnsupportedExtension))
    );
    assert_eq!(
        feed(&mut receiver, &lane_frame(false, 5, 100, &body), 7),
        Err(SessionError::Decode(Refusal::UnsupportedMessage))
    );
    // And the plain FRAME it does take is unchanged.
    assert_eq!(
        feed(&mut receiver, &lane_frame(true, 5, 100, &body), 8),
        Ok(std::vec!["sample 1".into()])
    );
    assert_eq!(receiver.expected_rx_sn(), 101);
}

// A heap session, so a message can arrive in fragments on the lane the session counts on.

fn heap_params() -> Params {
    Params {
        fragments: true,
        timeout_ms: 5000,
        message_limit: 4096,
        bounds: Bounds {
            payload: 1024,
            ..Bounds::DEMO
        },
        ..Params::DEMO
    }
}

fn heap_pair() -> (Two, Two) {
    let mk = |role, zid: &[u8; 8], sn, cookie: &[u8]| {
        Two::with_lanes(
            role,
            &Config {
                zid,
                lease_ms: 2000,
                initial_sn: sn,
                cookie,
            },
            heap_params(),
            2,
        )
        .expect("session")
    };
    let mut a = mk(Role::Connector, &[0xa1; 8], 100, &[]);
    let mut b = mk(Role::Listener, &[0xb2; 8], SN0, &[0xc0; 8]);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let syn = a.connect(0, &mut out).expect("c").batch(&out).to_vec();
    let ack = b
        .on_batch(&syn, 1, &mut out)
        .expect("s")
        .batch(&out)
        .to_vec();
    let osyn = a
        .on_batch(&ack, 2, &mut out)
        .expect("a")
        .batch(&out)
        .to_vec();
    let oack = b
        .on_batch(&osyn, 3, &mut out)
        .expect("o")
        .batch(&out)
        .to_vec();
    a.on_batch(&oack, 4, &mut out).expect("oa");
    let decl = b
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("d")
        .batch(&out)
        .to_vec();
    a.on_batch(&decl, 5, &mut out).expect("l");
    (a, b)
}

/// The fragments of one Put of `size` payload bytes on the default priority.
fn fragments(first_sn: u32, size: usize) -> Vec<Vec<u8>> {
    fragments_on(5, first_sn, size)
}

/// The same fragments on `priority`: the default has no extension, any other the mandatory one after the number.
fn fragments_on(priority: u8, first_sn: u32, size: usize) -> Vec<Vec<u8>> {
    fragments_lane(true, priority, first_sn, size)
}

/// The same fragments on a lane of either reliability.
fn fragments_lane(reliable: bool, priority: u8, first_sn: u32, size: usize) -> Vec<Vec<u8>> {
    let mut message = std::vec![0x7du8, 0x00, 0x81, 0x01];
    message.extend_from_slice(KEY.as_bytes());
    message.extend_from_slice(&[0x01 | 0x80, 0x43, 33]);
    message.extend_from_slice(&0i64.to_le_bytes());
    message.extend_from_slice(&1000i64.to_le_bytes());
    message.push(16);
    message.extend_from_slice(&GID);
    message.push((size & 0x7f) as u8 | 0x80);
    message.push((size >> 7) as u8);
    message.extend((0..size).map(|i| (i % 251) as u8));
    let mut out = Vec::new();
    let mut at = 0;
    let mut sn = first_sn;
    while at < message.len() {
        let room = 200usize;
        let end = (at + room).min(message.len());
        let more = end < message.len();
        let flags = 0x06
            | if reliable { 0x20 } else { 0 }
            | if more { 0x40 } else { 0 }
            | if priority == 5 { 0 } else { 0x80 };
        let mut body = std::vec![flags, sn as u8];
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

/// The storage of each run a `Two` session holds, one cell for each slot, as a link lends it.
struct Cells {
    cells: [Vec<u8>; 2],
}

impl Cells {
    fn new() -> Self {
        Self {
            cells: [std::vec![0u8; 4096], std::vec![0u8; 4096]],
        }
    }
}

/// Feeds one fragment the way a link does: the lane from the header, the slot the session names for it, and the
/// storage of that slot.
fn fragment_in(
    session: &mut Two,
    cells: &mut Cells,
    batch: &[u8],
    now: u64,
) -> Result<usize, SessionError> {
    let header = crate::zenoh_profile0::lane::decode_lane_fragment(batch, None).expect("header");
    let slot = session
        .run_slot(header.lane)
        .ok_or(SessionError::LaneLimit)?;
    let outcome = session.on_lane_fragment(batch, now, &mut cells.cells[slot])?;
    Ok(outcome.events.len())
}

#[test]
fn a_fragmented_message_moves_the_lane_counter_it_is_on() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments(100, 300);
    assert_eq!(parts.len(), 3);
    for (at, part) in parts.iter().enumerate() {
        let events =
            fragment_in(&mut receiver, &mut cells, part, 10 + at as u64).expect("fragment");
        assert_eq!(events, usize::from(at == 2), "fragment {at}");
    }
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 103);
    assert!(!receiver.reassembling());
    // The next number is taken and a number the fragments already used is refused.
    let body = put_body(1);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let next = lane_frame(true, 5, 103, &body);
    let taken = receiver.on_batch_with(&next, 20, &mut out, &mut cells.cells[0]);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    let replay = lane_frame(true, 5, 100, &body);
    assert_eq!(
        receiver
            .on_batch_with(&replay, 21, &mut out, &mut cells.cells[0])
            .err(),
        Some(SessionError::SequenceMismatch)
    );
}

#[test]
fn two_lanes_hold_two_runs_at_once_in_two_cells() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let first = fragments_on(2, 100, 300);
    let second = fragments_on(5, 100, 300);
    // The runs interleave, and each completes into a sample of its own.
    let mut samples = 0;
    for at in 0..3 {
        samples += fragment_in(&mut receiver, &mut cells, &first[at], 10 + at as u64).expect("p2");
        samples += fragment_in(&mut receiver, &mut cells, &second[at], 10 + at as u64).expect("p5");
        if at < 2 {
            assert!(receiver.reassembling());
        }
    }
    assert_eq!(samples, 2);
    assert!(!receiver.reassembling());
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        103
    );
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 103);
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 7,
            reliable: true
        }),
        100
    );
}

#[test]
fn the_slot_a_lane_is_given_is_the_slot_it_keeps() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let lane = |priority| Lane {
        priority,
        reliable: true,
    };
    // An idle session offers the first free slot to any lane.
    assert_eq!(receiver.run_slot(lane(2)), Some(0));
    assert_eq!(receiver.run_slot(lane(5)), Some(0));
    let first = fragments_on(2, 100, 300);
    fragment_in(&mut receiver, &mut cells, &first[0], 10).expect("first");
    // The lane of the open run keeps its slot, and another lane is offered the next free one.
    assert_eq!(receiver.run_slot(lane(2)), Some(0));
    assert_eq!(receiver.run_slot(lane(5)), Some(1));
    let second = fragments_on(5, 100, 300);
    fragment_in(&mut receiver, &mut cells, &second[0], 11).expect("second");
    assert_eq!(receiver.run_slot(lane(5)), Some(1));
    // Every slot is open, so a third lane has none, and the two open lanes keep theirs.
    assert_eq!(receiver.run_slot(lane(7)), None);
    assert_eq!(receiver.run_slot(lane(2)), Some(0));
}

#[test]
fn a_first_fragment_with_every_run_open_is_refused_as_lane_limit() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    for (priority, at) in [(2, 10), (5, 11)] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], at).expect("first");
    }
    // The session itself says so, given a cell for a slot that does not exist.
    let third = fragments_on(7, 100, 300);
    let mut spare = std::vec![0u8; 4096];
    assert_eq!(
        receiver.on_lane_fragment(&third[0], 12, &mut spare).err(),
        Some(SessionError::LaneLimit)
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 7,
            reliable: true
        }),
        100
    );
    // A wrong first number is judged before the room for it.
    let wrong = fragments_on(7, 105, 300);
    assert_eq!(
        receiver.on_lane_fragment(&wrong[0], 13, &mut spare).err(),
        Some(SessionError::SequenceMismatch)
    );
}

#[test]
fn a_session_with_lanes_refuses_a_fragment_through_the_one_cell_path() {
    let (_, mut receiver) = heap_pair();
    let mut cell = std::vec![0u8; 4096];
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments(100, 300);
    assert_eq!(
        receiver
            .on_batch_with(&parts[0], 10, &mut out, &mut cell)
            .err(),
        Some(SessionError::UnexpectedMessage)
    );
    assert!(!receiver.reassembling());
}

#[test]
fn a_reliable_frame_on_the_lane_of_an_open_run_ends_that_run_and_is_refused() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let body = put_body(1);
    let mut out = [0u8; MAX_BATCH_BYTES];
    for priority in [5u8, 2] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], 10).expect("first fragment");
        let lane = Lane {
            priority,
            reliable: true,
        };
        assert!(receiver.reassembling());
        let frame = lane_frame(true, priority, 101, &body);
        assert_eq!(
            receiver
                .on_batch_with(&frame, 11, &mut out, &mut cells.cells[0])
                .err(),
            Some(SessionError::UnexpectedMessage),
            "priority {priority}"
        );
        // The run of that lane is gone, and the counter did not move.
        assert!(!receiver.reassembling(), "priority {priority}");
        assert_eq!(receiver.lane_next(lane), 100);
    }
}

#[test]
fn a_frame_on_another_lane_is_taken_inside_an_open_run() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_on(2, 100, 300);
    fragment_in(&mut receiver, &mut cells, &parts[0], 10).expect("first fragment");
    assert!(receiver.reassembling());
    let body = put_body(1);
    // The run belongs to priority 2. A reliable FRAME on the default priority has its own counter and is
    // delivered, and neither it nor a best-effort FRAME ends the run.
    let reliable = lane_frame(true, 5, 100, &body);
    let taken = receiver.on_batch_with(&reliable, 11, &mut out, &mut cells.cells[1]);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    let best_effort = lane_frame(false, 5, 100, &body);
    let taken = receiver.on_batch_with(&best_effort, 12, &mut out, &mut cells.cells[1]);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    assert!(receiver.reassembling());
    for (at, part) in parts[1..].iter().enumerate() {
        fragment_in(&mut receiver, &mut cells, part, 13 + at as u64).expect("fragment");
    }
    assert!(!receiver.reassembling());
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        103
    );
}

#[test]
fn the_room_a_lane_frame_asks_for_covers_what_it_raises() {
    let (_, receiver) = subscribed();
    let body = put_body(1);
    // A FRAME with one Put raises one event and one sample on any lane, whether or not it is the default.
    for (reliable, priority) in [(true, 5), (true, 2), (false, 5), (false, 2)] {
        let batch = lane_frame(reliable, priority, 100, &body);
        assert_eq!(
            receiver.events_needed(&batch),
            (1, 1),
            "{reliable} p{priority}"
        );
    }
    // A best-effort FRAME the lane will drop still asks for the room of its drop, and a bad one asks for one.
    let bad = lane_frame(false, 2, 100, &[0xff]);
    assert_eq!(receiver.events_needed(&bad), (1, 0));
    // A reliable FRAME that fails raises nothing, because the link closes.
    let bad = lane_frame(true, 2, 100, &[0xff]);
    assert_eq!(receiver.events_needed(&bad), (0, 0));
}

/// A pair whose lease is far past any clock these tests reach, so only a run's timeout can end a run.
fn long_lease_pair() -> Two {
    let mk = |role, zid: &[u8; 8], sn, cookie: &[u8]| {
        Two::with_lanes(
            role,
            &Config {
                zid,
                lease_ms: 1_000_000,
                initial_sn: sn,
                cookie,
            },
            heap_params(),
            2,
        )
        .expect("session")
    };
    let mut a = mk(Role::Connector, &[0xa1; 8], 100, &[]);
    let mut b = mk(Role::Listener, &[0xb2; 8], SN0, &[0xc0; 8]);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let syn = a.connect(0, &mut out).expect("c").batch(&out).to_vec();
    let ack = b
        .on_batch(&syn, 1, &mut out)
        .expect("s")
        .batch(&out)
        .to_vec();
    let osyn = a
        .on_batch(&ack, 2, &mut out)
        .expect("a")
        .batch(&out)
        .to_vec();
    let oack = b
        .on_batch(&osyn, 3, &mut out)
        .expect("o")
        .batch(&out)
        .to_vec();
    a.on_batch(&oack, 4, &mut out).expect("oa");
    let decl = b
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("d")
        .batch(&out)
        .to_vec();
    a.on_batch(&decl, 5, &mut out).expect("l");
    b
}

#[test]
fn a_run_that_outlives_the_timeout_is_refused_and_every_late_run_is_released() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    for (priority, at) in [(2u8, 1000u64), (5, 2000)] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], at).expect("first fragment");
    }
    assert!(receiver.reassembling());
    // The timeout is 5000 ms from a run's first fragment: 6000 for the first run and 7000 for the second. At
    // 6000 the first is on its deadline and the second is well inside it.
    assert!(receiver.tick(6000, &mut out).is_ok());
    assert!(receiver.reassembling());
    // At 6001 the first run is late. It is refused and released, and the other stays open.
    assert_eq!(
        receiver.tick(6001, &mut out).err(),
        Some(SessionError::Fragment(FragmentError::ReassemblyTimeout))
    );
    let lane = |priority| Lane {
        priority,
        reliable: true,
    };
    assert_eq!(
        receiver.run_slot(lane(2)),
        Some(0),
        "the late run's slot is free again"
    );
    assert_eq!(
        receiver.run_slot(lane(5)),
        Some(1),
        "the other run is still open"
    );
    assert!(receiver.reassembling());
    // At 7001 the second is late too.
    assert_eq!(
        receiver.tick(7001, &mut out).err(),
        Some(SessionError::Fragment(FragmentError::ReassemblyTimeout))
    );
    assert!(!receiver.reassembling());
    // Neither lane's counter moved, so a new message may start at the same number.
    assert_eq!(receiver.lane_next(lane(2)), 100);
    assert_eq!(receiver.lane_next(lane(5)), 100);
}

#[test]
fn two_late_runs_are_refused_by_one_tick_and_both_released() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    for priority in [2u8, 5] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], 1000).expect("first fragment");
    }
    assert_eq!(
        receiver.tick(6001, &mut out).err(),
        Some(SessionError::Fragment(FragmentError::ReassemblyTimeout))
    );
    assert!(!receiver.reassembling());
}

#[test]
fn closing_the_session_releases_every_run() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    for priority in [2u8, 5] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], 10).expect("first fragment");
    }
    assert!(receiver.reassembling());
    receiver.close(0, &mut out).expect("close");
    assert!(!receiver.reassembling());
}

#[test]
fn a_refused_fragment_header_ends_the_run_of_its_lane_and_no_other() {
    let lane = |priority| Lane {
        priority,
        reliable: true,
    };
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    for priority in [2u8, 5] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], 10).expect("first fragment");
    }
    // Both runs are open, so a third lane has no slot. The slot of an open run and the first free slot can be
    // the same number, so a lane with no run of its own is the witness of what is open.
    assert_eq!(receiver.run_slot(lane(7)), None, "every run is open");
    // A fragment of priority 2 with no data is refused, and the run of priority 2 ends with it.
    let parts = fragments_on(2, 100, 300);
    let empty = parts[1][..4].to_vec();
    assert_eq!(
        receiver
            .on_lane_fragment(&empty, 11, &mut cells.cells[0])
            .err(),
        Some(SessionError::Decode(Refusal::MalformedMessage))
    );
    assert_eq!(
        receiver.run_slot(lane(7)),
        Some(0),
        "the run of priority 2 is gone"
    );
    assert_eq!(
        receiver.run_slot(lane(5)),
        Some(1),
        "the run of priority 5 is open"
    );
    assert!(receiver.reassembling());
    // A header that names no lane, a priority of 8, ends no run. Priority 7 has none open, so a free slot
    // before and after shows that no run was released: slot 0 is free and slot 1 is still open.
    let mut unreadable = fragments_on(2, 100, 300)[1].clone();
    unreadable[3] = 8;
    assert_eq!(
        receiver
            .on_lane_fragment(&unreadable, 12, &mut cells.cells[1])
            .err(),
        Some(SessionError::Decode(Refusal::UnsupportedExtension))
    );
    assert_eq!(
        receiver.run_slot(lane(5)),
        Some(1),
        "the run of priority 5 is still open"
    );
    assert_eq!(receiver.run_slot(lane(7)), Some(0));
    assert_eq!(receiver.lane_next(lane(2)), 100);
}

/// What one fragment did on a best-effort lane, as the exam spells it: `sample`, or `drop <cause>`.
fn best_effort_in(
    session: &mut Two,
    cells: &mut Cells,
    batch: &[u8],
    now: u64,
) -> Result<Vec<std::string::String>, SessionError> {
    let header = crate::zenoh_profile0::lane::decode_lane_fragment(batch, None).expect("header");
    let slot = session.run_slot(header.lane).unwrap_or(0);
    let outcome = session.on_lane_fragment(batch, now, &mut cells.cells[slot])?;
    Ok(spell(outcome.events.iter()))
}

fn spell<'a>(events: impl Iterator<Item = &'a Event<'a>>) -> Vec<std::string::String> {
    events
        .map(|event| match event {
            Event::SampleStored { .. } | Event::SampleDelivered { .. } => "sample".into(),
            Event::Dropped {
                cause: DropCause::Completed(class),
                ..
            } => std::format!("drop completed:{class}"),
            Event::Dropped { cause, .. } => std::format!("drop {}", cause.name()),
            other => std::format!("{other:?}"),
        })
        .collect()
}

fn best_effort(priority: u8) -> Lane {
    Lane {
        priority,
        reliable: false,
    }
}

#[test]
fn a_best_effort_run_joins_into_a_sample_and_moves_its_own_counter() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    assert_eq!(parts.len(), 3);
    for (at, part) in parts.iter().enumerate() {
        let events = best_effort_in(&mut receiver, &mut cells, part, 10).expect("fragment");
        assert_eq!(
            events,
            if at == 2 {
                ["sample"].to_vec()
            } else {
                Vec::new()
            }
        );
    }
    assert_eq!(receiver.lane_next(best_effort(2)), 103);
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        100
    );
    assert!(!receiver.reassembling());
}

#[test]
fn a_gap_in_a_best_effort_run_drops_it_and_discards_through_the_final_fragment() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 900);
    assert!(parts.len() >= 5);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 10).expect("first");
    // The second fragment is lost. The third is ahead but not the run's next number.
    let broken = best_effort_in(&mut receiver, &mut cells, &parts[2], 10).expect("gap");
    assert_eq!(broken, ["drop fragment-sequence"]);
    assert!(!receiver.reassembling());
    assert_eq!(receiver.lane_next(best_effort(2)), 103);
    let last = parts.len() - 1;
    for part in &parts[3..last] {
        let events = best_effort_in(&mut receiver, &mut cells, part, 10).expect("leftover");
        assert_eq!(events, ["drop discarded"]);
    }
    let events = best_effort_in(&mut receiver, &mut cells, &parts[last], 10).expect("final");
    assert_eq!(events, ["drop discarded"]);
    // The discard ended with the final fragment, so the next message is taken.
    let next = fragments_lane(false, 2, 100 + parts.len() as u32, 300);
    for (at, part) in next.iter().enumerate() {
        let events = best_effort_in(&mut receiver, &mut cells, part, 11).expect("next");
        assert_eq!(
            events,
            if at == 2 {
                ["sample"].to_vec()
            } else {
                Vec::new()
            }
        );
    }
}

#[test]
fn a_best_effort_fragment_that_is_not_ahead_is_dropped_and_the_run_stays_open() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 10).expect("first");
    let events = best_effort_in(&mut receiver, &mut cells, &parts[0], 11).expect("replay");
    assert_eq!(events, ["drop stale-sequence"]);
    assert!(receiver.reassembling());
    assert_eq!(receiver.lane_next(best_effort(2)), 101);
    let mut samples = 0;
    for part in &parts[1..] {
        samples += best_effort_in(&mut receiver, &mut cells, part, 12)
            .expect("rest")
            .len();
    }
    assert_eq!(samples, 1);
}

#[test]
fn a_best_effort_first_fragment_with_every_run_open_is_dropped_and_discarded() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    for priority in [2u8, 7] {
        let parts = fragments_on(priority, 100, 300);
        fragment_in(&mut receiver, &mut cells, &parts[0], 10).expect("reliable first");
    }
    let parts = fragments_lane(false, 5, 100, 300);
    let events = best_effort_in(&mut receiver, &mut cells, &parts[0], 11).expect("first");
    assert_eq!(events, ["drop lane-limit"]);
    assert_eq!(receiver.lane_next(best_effort(5)), 101);
    for (at, part) in parts[1..].iter().enumerate() {
        let events = best_effort_in(&mut receiver, &mut cells, part, 11).expect("leftover");
        assert_eq!(events, ["drop discarded"], "fragment {at}");
    }
    // The reliable runs were not disturbed.
    assert!(receiver.reassembling());
}

#[test]
fn a_best_effort_run_that_starts_late_completes_as_a_bad_message_and_is_dropped_by_class() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    // The first fragment is lost, so the run starts at the second, which the lane takes as ahead.
    let mut seen = Vec::new();
    for part in &parts[1..] {
        seen.extend(best_effort_in(&mut receiver, &mut cells, part, 10).expect("fragment"));
    }
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("drop completed:"), "{seen:?}");
    assert_eq!(receiver.lane_next(best_effort(2)), 103);
    assert!(!receiver.reassembling());
}

#[test]
fn a_best_effort_run_that_outlives_the_timeout_is_dropped_by_the_tick_and_the_lane_discards() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 1000).expect("first");
    let on_time = receiver.tick(6000, &mut out).expect("on the deadline");
    assert!(on_time.events.is_empty());
    assert!(receiver.reassembling());
    let late = receiver
        .tick(6001, &mut out)
        .expect("late is a drop, not a refusal");
    assert_eq!(spell(late.events.iter()), ["drop reassembly-timeout"]);
    assert!(!receiver.reassembling());
    // The leftovers of the message are discarded, and the final one ends the discard.
    assert_eq!(
        best_effort_in(&mut receiver, &mut cells, &parts[1], 6002).expect("second"),
        ["drop discarded"]
    );
    assert_eq!(
        best_effort_in(&mut receiver, &mut cells, &parts[2], 6002).expect("final"),
        ["drop discarded"]
    );
}

#[test]
fn a_best_effort_fragment_after_the_timeout_reports_the_timeout_and_is_discarded() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 1000).expect("first");
    let events = best_effort_in(&mut receiver, &mut cells, &parts[1], 6001).expect("late");
    assert_eq!(events, ["drop reassembly-timeout", "drop discarded"]);
    assert!(!receiver.reassembling());
}

#[test]
fn a_late_best_effort_run_and_a_late_reliable_run_end_differently_in_one_tick() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let be = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &be[0], 1000).expect("best-effort first");
    let reliable = fragments_on(5, 100, 300);
    fragment_in(&mut receiver, &mut cells, &reliable[0], 1000).expect("reliable first");
    assert_eq!(
        receiver.tick(6001, &mut out).err(),
        Some(SessionError::Fragment(FragmentError::ReassemblyTimeout))
    );
    assert!(!receiver.reassembling(), "both runs are released");
    // The best-effort lane discards after the refusal, as it does after a drop.
    assert_eq!(
        best_effort_in(&mut receiver, &mut cells, &be[1], 6002).expect("leftover"),
        ["drop discarded"]
    );
}

#[test]
fn a_best_effort_frame_on_the_lane_of_an_open_run_drops_the_run_and_is_taken() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 10).expect("first");
    let body = put_body(1);
    let frame = lane_frame(false, 2, 101, &body);
    let taken = receiver
        .on_batch_with(&frame, 11, &mut out, &mut cells.cells[1])
        .expect("frame");
    assert_eq!(
        spell(taken.events.iter()),
        ["drop frame-during-run", "sample"]
    );
    assert!(!receiver.reassembling());
    assert_eq!(receiver.lane_next(best_effort(2)), 102);
    // A best-effort FRAME on another lane leaves the run alone.
    best_effort_in(
        &mut receiver,
        &mut cells,
        &fragments_lane(false, 2, 102, 300)[0],
        12,
    )
    .expect("again");
    let other = lane_frame(false, 3, 100, &body);
    receiver
        .on_batch_with(&other, 13, &mut out, &mut cells.cells[1])
        .expect("other lane");
    assert!(receiver.reassembling());
}

#[test]
fn a_refused_best_effort_header_keeps_the_run_of_its_lane() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 10).expect("first");
    let empty = parts[1][..4].to_vec();
    assert_eq!(
        receiver
            .on_lane_fragment(&empty, 11, &mut cells.cells[0])
            .err(),
        Some(SessionError::Decode(Refusal::MalformedMessage))
    );
    assert!(receiver.reassembling());
    assert_eq!(receiver.lane_next(best_effort(2)), 101);
}

#[test]
fn a_reliable_and_a_best_effort_run_of_one_priority_are_two_runs() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let reliable = fragments_on(2, 100, 300);
    let be = fragments_lane(false, 2, 100, 300);
    let mut samples = 0;
    for at in 0..3 {
        samples += fragment_in(&mut receiver, &mut cells, &reliable[at], 10).expect("reliable");
        samples += best_effort_in(&mut receiver, &mut cells, &be[at], 10)
            .expect("best-effort")
            .len();
    }
    assert_eq!(samples, 2);
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 2,
            reliable: true
        }),
        103
    );
    assert_eq!(receiver.lane_next(best_effort(2)), 103);
}

#[test]
fn a_gap_on_the_final_fragment_drops_the_run_and_starts_no_discard() {
    let (_, mut receiver) = heap_pair();
    let mut cells = Cells::new();
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 10).expect("first");
    // The second fragment is lost and the final one arrives: the message is over, so nothing follows to discard.
    let events = best_effort_in(&mut receiver, &mut cells, &parts[2], 10).expect("final");
    assert_eq!(events, ["drop fragment-sequence"]);
    let next = fragments_lane(false, 2, 103, 300);
    for (at, part) in next.iter().enumerate() {
        let events = best_effort_in(&mut receiver, &mut cells, part, 11).expect("next");
        assert_eq!(
            events,
            if at == 2 {
                ["sample"].to_vec()
            } else {
                Vec::new()
            }
        );
    }
}

#[test]
fn a_tick_that_writes_a_keep_alive_reports_the_drop_of_a_late_best_effort_run_too() {
    let mut receiver = long_lease_pair();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_lane(false, 2, 100, 300);
    best_effort_in(&mut receiver, &mut cells, &parts[0], 1000).expect("first");
    // The lease is 1,000,000 ms, so a quarter of it is long past by the time the run is late.
    let due = receiver.tick(300_000, &mut out).expect("tick");
    assert_ne!(due.sent, 0, "a keep-alive is written");
    assert_eq!(spell(due.events.iter()), ["drop reassembly-timeout"]);
    assert!(!receiver.reassembling());
}

/// A receiver with one event slot and two runs, open and subscribed, with a lease no test clock reaches.
type OneSlot = SessionOf<1, 2, MAX_KEY_BYTES, 1, 2>;

fn one_slot_receiver() -> OneSlot {
    let mk = |role, zid: &[u8; 8], sn, cookie: &[u8]| {
        OneSlot::with_lanes(
            role,
            &Config {
                zid,
                lease_ms: 1_000_000,
                initial_sn: sn,
                cookie,
            },
            Params {
                events: 1,
                ..heap_params()
            },
            2,
        )
        .expect("session")
    };
    let mut a = mk(Role::Connector, &[0xa1; 8], 100, &[]);
    let mut b = mk(Role::Listener, &[0xb2; 8], SN0, &[0xc0; 8]);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let syn = a.connect(0, &mut out).expect("c").batch(&out).to_vec();
    let ack = b
        .on_batch(&syn, 1, &mut out)
        .expect("s")
        .batch(&out)
        .to_vec();
    let osyn = a
        .on_batch(&ack, 2, &mut out)
        .expect("a")
        .batch(&out)
        .to_vec();
    let oack = b
        .on_batch(&osyn, 3, &mut out)
        .expect("o")
        .batch(&out)
        .to_vec();
    a.on_batch(&oack, 4, &mut out).expect("oa");
    let decl = b
        .send_declare_subscriber(1, KEY, &mut out)
        .expect("d")
        .batch(&out)
        .to_vec();
    a.on_batch(&decl, 5, &mut out).expect("l");
    b
}

#[test]
fn a_drop_never_costs_the_delivery_of_a_frame_that_fills_the_events() {
    let mut receiver = one_slot_receiver();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_lane(false, 2, 100, 300);
    receiver
        .on_lane_fragment(&parts[0], 10, &mut cells.cells[0])
        .expect("first");
    // The FRAME carries one Put and the session has one event slot, so the drop of the run has no room.
    let frame = lane_frame(false, 2, 101, &put_body(1));
    let taken = receiver
        .on_batch_with(&frame, 11, &mut out, &mut cells.cells[1])
        .expect("a FRAME that fills the events is delivered");
    assert_eq!(spell(taken.events.iter()), ["sample"]);
    assert!(!receiver.reassembling(), "the run is gone either way");
    assert_eq!(receiver.lane_next(best_effort(2)), 102);
}

#[test]
fn a_drop_never_costs_a_failed_frame_its_own_drop() {
    let mut receiver = one_slot_receiver();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments_lane(false, 2, 100, 300);
    receiver
        .on_lane_fragment(&parts[0], 10, &mut cells.cells[0])
        .expect("first");
    // A FRAME of garbage is dropped as `completed`, and that report outranks the one for the run it ended.
    let frame = lane_frame(false, 2, 101, &[0xff, 0xff]);
    let taken = receiver
        .on_batch_with(&frame, 11, &mut out, &mut cells.cells[1])
        .expect("a best-effort FRAME that fails is a drop");
    let seen = spell(taken.events.iter());
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("drop completed:"), "{seen:?}");
    assert!(!receiver.reassembling());
}

#[test]
fn late_best_effort_runs_are_released_when_the_events_have_room_for_one_report() {
    let mut receiver = one_slot_receiver();
    let mut cells = Cells::new();
    let mut out = [0u8; MAX_BATCH_BYTES];
    for (priority, cell) in [(2u8, 0usize), (3, 1)] {
        let parts = fragments_lane(false, priority, 100, 300);
        receiver
            .on_lane_fragment(&parts[0], 1000, &mut cells.cells[cell])
            .expect("first");
    }
    let late = receiver
        .tick(6001, &mut out)
        .expect("a drop is not an error when the events are full");
    assert_eq!(
        late.events.len(),
        1,
        "one report fits, the other is not kept"
    );
    assert!(!receiver.reassembling(), "both runs are released");
    // Both lanes discard their leftovers.
    for priority in [2u8, 3] {
        let parts = fragments_lane(false, priority, 100, 300);
        let events = receiver
            .on_lane_fragment(&parts[1], 6002, &mut cells.cells[0])
            .expect("leftover");
        assert_eq!(spell(events.events.iter()), ["drop discarded"]);
    }
}

/// One best-effort FRAGMENT of priority 2 with the given number: the number is a LEB128 value, so it may exceed a byte.
fn edge_fragment(sn: u32, more: bool) -> Vec<u8> {
    let mut body = std::vec![0x06 | if more { 0x40 } else { 0 } | 0x80];
    let mut rest = sn;
    loop {
        let byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest == 0 {
            body.push(byte);
            break;
        }
        body.push(byte | 0x80);
    }
    body.extend_from_slice(&[0x31, 2, 1, 2, 3]);
    body
}

#[test]
fn a_best_effort_fragment_is_ahead_up_to_half_the_range_and_stale_from_there() {
    // Upstream measures from the last number taken, so a number is ahead by 1 to 2^31 - 1 of it. The count held
    // here is one more, so the last number ahead is `next + 2^31 - 2` and the first stale one is `next + 2^31 - 1`.
    let half = 1u32 << 31;
    for (offset, ahead) in [
        (0, true),
        (1, true),
        (half - 2, true),
        (half - 1, false),
        (half, false),
    ] {
        let (_, mut receiver) = heap_pair();
        let mut cells = Cells::new();
        let lane = best_effort(2);
        let sn = receiver.lane_next(lane).wrapping_add(offset);
        let events = best_effort_in(&mut receiver, &mut cells, &edge_fragment(sn, true), 10)
            .expect("a best-effort fragment is never refused for its number");
        assert_eq!(receiver.reassembling(), ahead, "offset {offset}");
        assert_eq!(
            events,
            if ahead {
                Vec::new()
            } else {
                ["drop stale-sequence"].to_vec()
            },
            "offset {offset}"
        );
        let counted = if ahead {
            sn.wrapping_add(1)
        } else {
            sn.wrapping_sub(offset)
        };
        assert_eq!(receiver.lane_next(lane), counted, "offset {offset}");
    }
}
