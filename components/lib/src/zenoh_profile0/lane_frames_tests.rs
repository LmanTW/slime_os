//! Host tests for a FRAME taken by its lane. The scenarios are the ones of `scripts/lib/zenoh_lanes_exam.py`
//! that concern a whole FRAME: a reliable lane takes exactly its next number, and a best-effort lane takes a
//! number ahead, counts the gap and drops one that is not ahead.

use super::*;
use crate::zenoh_profile0::encode::FrameEncoder;
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
fn open_pair() -> (Session, Session) {
    let mut a = Session::with_lanes(
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
    let mut b = Session::with_lanes(
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
fn subscribed() -> (Session, Session) {
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

fn feed(
    session: &mut Session,
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

fn heap_pair() -> (Session, Session) {
    let mk = |role, zid: &[u8; 8], sn, cookie: &[u8]| {
        Session::with_lanes(
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

fn fragments(first_sn: u32, size: usize) -> Vec<Vec<u8>> {
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
        let mut body = std::vec![0x06 | 0x20 | if more { 0x40 } else { 0 }, sn as u8];
        body.extend_from_slice(&message[at..end]);
        out.push(body);
        at = end;
        sn += 1;
    }
    out
}

#[test]
fn a_fragmented_message_moves_the_default_lane_counter() {
    let (_, mut receiver) = heap_pair();
    let mut cell = std::vec![0u8; 4096];
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments(100, 300);
    assert_eq!(parts.len(), 3);
    for (at, part) in parts.iter().enumerate() {
        let outcome = receiver
            .on_batch_with(part, 10 + at as u64, &mut out, &mut cell)
            .expect("fragment");
        assert_eq!(outcome.events.len(), usize::from(at == 2), "fragment {at}");
    }
    // One counter serves the plain path, the lane path and the fragments, so all three agree.
    assert_eq!(receiver.expected_rx_sn(), 103);
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 103);
    let body = put_body(1);
    let next = lane_frame(true, 5, 103, &body);
    let taken = receiver.on_batch_with(&next, 20, &mut out, &mut cell);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    // A number the fragments already used is refused, not taken again.
    let replay = lane_frame(true, 5, 100, &body);
    assert_eq!(
        receiver
            .on_batch_with(&replay, 21, &mut out, &mut cell)
            .err(),
        Some(SessionError::SequenceMismatch)
    );
}

#[test]
fn a_reliable_frame_on_the_lane_of_an_open_run_ends_the_run_and_is_refused() {
    let (_, mut receiver) = heap_pair();
    let mut cell = std::vec![0u8; 4096];
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments(100, 300);
    receiver
        .on_batch_with(&parts[0], 10, &mut out, &mut cell)
        .expect("first fragment");
    assert!(receiver.reassembling());
    let body = put_body(1);
    let frame = lane_frame(true, 5, 101, &body);
    assert_eq!(
        receiver
            .on_batch_with(&frame, 11, &mut out, &mut cell)
            .err(),
        Some(SessionError::UnexpectedMessage)
    );
    // The run is gone, as it is for a plain FRAME, and the counter did not move.
    assert!(!receiver.reassembling());
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 100);
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

#[test]
fn a_frame_on_another_lane_is_taken_inside_an_open_run() {
    let (_, mut receiver) = heap_pair();
    let mut cell = std::vec![0u8; 4096];
    let mut out = [0u8; MAX_BATCH_BYTES];
    let parts = fragments(100, 300);
    receiver
        .on_batch_with(&parts[0], 10, &mut out, &mut cell)
        .expect("first fragment");
    assert!(receiver.reassembling());
    // The run belongs to the default lane. A reliable FRAME on priority 2 has its own counter and is delivered,
    // and a best-effort FRAME on the default priority does too. Neither ends the run.
    let body = put_body(1);
    let reliable = lane_frame(true, 2, 100, &body);
    let taken = receiver.on_batch_with(&reliable, 11, &mut out, &mut cell);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    let best_effort = lane_frame(false, 5, 100, &body);
    let taken = receiver.on_batch_with(&best_effort, 12, &mut out, &mut cell);
    assert_eq!(taken.map(|outcome| outcome.events.len()), Ok(1));
    assert!(receiver.reassembling());
    // The run goes on and completes, so the other lanes did not disturb it.
    for (at, part) in parts[1..].iter().enumerate() {
        receiver
            .on_batch_with(part, 13 + at as u64, &mut out, &mut cell)
            .expect("fragment");
    }
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 103);
}

#[test]
fn fragments_count_from_the_default_lane_and_not_from_another() {
    let (_, mut receiver) = heap_pair();
    let mut cell = std::vec![0u8; 4096];
    let mut out = [0u8; MAX_BATCH_BYTES];
    let body = put_body(1);
    // Move two other lanes, one at the lowest index and one next to the default, so the counters differ: both
    // are at 101 and the default lane is at 100.
    for priority in [0, 2, 7] {
        let moved = lane_frame(true, priority, 100, &body);
        receiver
            .on_batch_with(&moved, 10, &mut out, &mut cell)
            .expect("another lane");
    }
    let moved_best_effort = lane_frame(false, 5, 100, &body);
    receiver
        .on_batch_with(&moved_best_effort, 10, &mut out, &mut cell)
        .expect("best-effort");
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 0,
            reliable: true
        }),
        101
    );
    assert_eq!(
        receiver.lane_next(Lane {
            priority: 5,
            reliable: false
        }),
        101
    );
    assert_eq!(receiver.lane_next(Lane::DEFAULT), 100);
    // A run that starts at 101 is not the default lane's next number, so its first fragment is refused.
    let parts = fragments(101, 300);
    assert_eq!(
        receiver
            .on_batch_with(&parts[0], 11, &mut out, &mut cell)
            .err(),
        Some(SessionError::SequenceMismatch)
    );
    // One that starts at 100 is taken.
    let parts = fragments(100, 300);
    assert!(
        receiver
            .on_batch_with(&parts[0], 12, &mut out, &mut cell)
            .is_ok()
    );
}
