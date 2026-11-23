//! Host tests for reassembly: the storage is the component's, the deadline runs from the first fragment,
//! and every way a run can end leaves the storage free for the next message.

use super::*;
use crate::zenoh_profile0::fragment::{decode_fragment, tests as codec};
use std::vec::Vec;

const BATCH: usize = 2048;
const FIRST: u32 = 1000;

fn fragments(size: usize, first: u32) -> (Vec<u8>, Vec<Vec<u8>>) {
    let message = codec::full_key_put("a/b", size);
    let bodies = codec::split(&message, BATCH, first);
    (message, bodies)
}

/// Feeds a whole run and returns the joined message.
fn join(
    reassembly: &mut Reassembly,
    storage: &mut [u8],
    bodies: &[Vec<u8>],
    first: u32,
    now: u64,
) -> Vec<u8> {
    for (index, body) in bodies.iter().enumerate() {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        let progress = reassembly
            .accept(&fragment, storage, first, now)
            .expect("accepted");
        assert_eq!(progress == Progress::Open, index + 1 < bodies.len());
    }
    let (message, next) = reassembly.finish(storage).expect("finished");
    assert_eq!(next, first.wrapping_add(bodies.len() as u32));
    message.to_vec()
}

#[test]
fn a_run_joins_into_the_front_of_the_supplied_storage() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    assert_eq!(
        join(&mut reassembly, &mut storage, &bodies, FIRST, 0),
        message
    );
    assert!(!reassembly.is_open());
}

#[test]
fn the_storage_of_exactly_one_message_serves_message_after_message() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    for round in 0..4u32 {
        let (_, bodies) = fragments(5000, FIRST + round * bodies.len() as u32);
        let first = FIRST + round * 3;
        assert_eq!(
            join(
                &mut reassembly,
                &mut storage,
                &bodies,
                first,
                u64::from(round)
            ),
            message
        );
    }
}

#[test]
fn storage_too_small_refuses_the_message_and_frees_it() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len() - 1];
    let mut reassembly = Reassembly::new(5000, message.len());
    let mut error = None;
    for body in &bodies {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        if let Err(refused) = reassembly.accept(&fragment, &mut storage, FIRST, 0) {
            error = Some(refused);
            break;
        }
    }
    assert_eq!(error, Some(FragmentError::OutOfMemory));
    assert!(!reassembly.is_open());
    assert!(reassembly.is_empty());
}

#[test]
fn a_message_over_the_declared_limit_is_refused_though_the_storage_would_hold_it() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len() * 2];
    let mut reassembly = Reassembly::new(5000, message.len() - 1);
    let mut class = "";
    for body in &bodies {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        if let Err(refused) = reassembly.accept(&fragment, &mut storage, FIRST, 0) {
            class = refused.class();
            break;
        }
    }
    assert_eq!(class, "over-bound");
    assert!(!reassembly.is_open());
}

fn first_error(
    reassembly: &mut Reassembly,
    storage: &mut [u8],
    run: &[Vec<u8>],
    first: u32,
    now: u64,
) -> Option<&'static str> {
    for body in run {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        if let Err(refused) = reassembly.accept(&fragment, storage, first, now) {
            return Some(refused.class());
        }
    }
    None
}

#[test]
fn a_gap_a_duplicate_and_a_step_back_are_refused_as_fragment_sequence() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let cases: [(&str, Vec<Vec<u8>>); 3] = [
        ("gap", std::vec![bodies[0].clone(), bodies[2].clone()]),
        (
            "duplicate",
            std::vec![bodies[0].clone(), bodies[0].clone(), bodies[2].clone()],
        ),
        (
            "backward",
            std::vec![bodies[0].clone(), bodies[1].clone(), bodies[0].clone()],
        ),
    ];
    for (label, run) in cases {
        let mut reassembly = Reassembly::new(5000, message.len());
        assert_eq!(
            first_error(&mut reassembly, &mut storage, &run, FIRST, 0),
            Some("fragment-sequence"),
            "{label}"
        );
        assert!(!reassembly.is_open(), "{label} frees the run");
    }
}

#[test]
fn the_first_fragment_must_be_the_sessions_next_sequence_number() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    for expected in [FIRST + 1000, FIRST - 1, FIRST + 1, 0] {
        let mut reassembly = Reassembly::new(5000, message.len());
        assert_eq!(
            first_error(&mut reassembly, &mut storage, &bodies, expected, 0),
            Some("sequence-mismatch"),
            "{expected}"
        );
        assert!(!reassembly.is_open());
    }
    // Across the wrap, the expected number is taken as it stands.
    let (message, bodies) = fragments(5000, 0xFFFF_FFFE);
    let mut reassembly = Reassembly::new(5000, message.len());
    assert_eq!(
        join(&mut reassembly, &mut storage, &bodies, 0xFFFF_FFFE, 0),
        message
    );
}

#[test]
fn a_run_ends_at_the_final_fragment_and_a_fragment_after_it_is_refused() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    // An interior fragment that says no more follows ends the run early: the next is refused.
    let mut early = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
    early.more = false;
    assert_eq!(
        reassembly.accept(&early, &mut storage, FIRST, 0),
        Ok(Progress::Complete(early.data.len()))
    );
    let next = decode_fragment(&bodies[1], Some(BATCH)).expect("fragment");
    assert_eq!(
        reassembly.accept(&next, &mut storage, FIRST, 0),
        Err(FragmentError::FragmentSequence)
    );
    assert!(!reassembly.is_open());
}

#[test]
fn the_deadline_is_measured_from_the_first_fragment_and_a_continuation_does_not_refresh_it() {
    let (message, bodies) = fragments(5000, FIRST);
    for timeout in [5000u64, 250, 1, 65_536, 1 << 32, (1 << 63) - 1] {
        let started = 7_000_000u64;
        let edge = started + timeout;
        let mut storage = std::vec![0u8; message.len()];
        // The middle fragment arrives a millisecond before the edge; the last exactly at it.
        let mut reassembly = Reassembly::new(timeout, message.len());
        let times = [started, edge - 1, edge];
        for (index, body) in bodies.iter().enumerate() {
            let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
            reassembly
                .accept(&fragment, &mut storage, FIRST, times[index])
                .expect("on time");
        }
        let (joined, _) = reassembly.finish(&storage).expect("finished");
        assert_eq!(joined, message, "{timeout}");
        // The same run with the last fragment a millisecond later is refused, whatever came between.
        let mut reassembly = Reassembly::new(timeout, message.len());
        for (index, body) in bodies.iter().enumerate() {
            let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
            let at = [started, edge - 1, edge + 1][index];
            let result = reassembly.accept(&fragment, &mut storage, FIRST, at);
            if index < 2 {
                result.expect("early enough");
            } else {
                assert_eq!(result, Err(FragmentError::ReassemblyTimeout), "{timeout}");
            }
        }
        assert!(!reassembly.is_open(), "{timeout} releases its storage");
    }
}

#[test]
fn a_first_fragment_after_the_clock_passed_the_timeout_is_not_late() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    // The session has been up for two hours; the deadline comes from this run, not from the clock.
    assert_eq!(
        join(&mut reassembly, &mut storage, &bodies, FIRST, 7_200_000),
        message
    );
}

#[test]
fn a_last_fragment_that_still_says_more_waits_and_expires() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    for (index, body) in bodies.iter().enumerate() {
        let mut fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        fragment.more = true;
        assert_eq!(
            reassembly.accept(&fragment, &mut storage, FIRST, 100),
            Ok(Progress::Open),
            "{index}"
        );
    }
    assert!(reassembly.is_open());
    assert_eq!(reassembly.deadline(), Some(5100));
    assert!(!reassembly.expired(5100));
    assert!(reassembly.expired(5101));
    reassembly.release();
    assert!(!reassembly.is_open());
    assert_eq!(reassembly.deadline(), None);
}

#[test]
fn a_single_final_fragment_is_a_complete_message() {
    let message = codec::full_key_put("a/b", 100);
    let bodies = codec::split(&message, BATCH, FIRST);
    assert_eq!(bodies.len(), 1);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    assert_eq!(
        join(&mut reassembly, &mut storage, &bodies, FIRST, 0),
        message
    );
    let (_, next) = {
        let fragment = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
        let mut other = Reassembly::new(5000, message.len());
        other
            .accept(&fragment, &mut storage, 0xFFFF_FFFF, 0)
            .expect_err("wrong number");
        let bodies = codec::split(&message, BATCH, 0xFFFF_FFFF);
        let fragment = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
        other
            .accept(&fragment, &mut storage, 0xFFFF_FFFF, 0)
            .expect("accepted");
        other.finish(&storage).expect("finished")
    };
    assert_eq!(next, 0, "the expected number wraps to zero");
}

#[test]
fn a_run_whose_slices_are_shorter_than_the_maximum_is_taken() {
    // A sender may flush early: a slice is at most the room, not exactly that.
    let message = codec::full_key_put("a/b", 5000);
    let mut bodies = Vec::new();
    let mut at = 0;
    for (step, take) in [1000usize, 1, 1500, usize::MAX, usize::MAX]
        .into_iter()
        .enumerate()
    {
        let sn = FIRST + step as u32;
        // A slice is at most the batch less the stream length and the fragment's own header.
        let room = BATCH
            - crate::zenoh_profile0::STREAM_LENGTH_BYTES
            - 1
            - codec::leb(u64::from(sn)).len();
        let take = take.min(room).min(message.len() - at);
        let more = at + take < message.len();
        let mut body = std::vec![
            crate::zenoh_profile0::fragment::ID_FRAGMENT | 0x20 | if more { 0x40 } else { 0 }
        ];
        body.extend(codec::leb(u64::from(sn)));
        body.extend(&message[at..at + take]);
        bodies.push(body);
        at += take;
        if !more {
            break;
        }
    }
    assert!(bodies.len() >= 4);
    let mut storage = std::vec![0u8; message.len()];
    let mut reassembly = Reassembly::new(5000, message.len());
    assert_eq!(
        join(&mut reassembly, &mut storage, &bodies, FIRST, 0),
        message
    );
}

// A `Run` holds one run's state and takes its timeout and limit from the caller, so a table of runs shares
// them. These tests drive it directly.

const TIMEOUT: u64 = 5000;

fn run_join(
    run: &mut Run,
    storage: &mut [u8],
    bodies: &[Vec<u8>],
    first: u32,
    now: u64,
    limit: usize,
) {
    for body in bodies {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        run.accept(&fragment, storage, first, now, TIMEOUT, limit)
            .expect("accepted");
    }
}

#[test]
fn a_run_joins_a_message_as_a_reassembly_does() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut run = Run::new();
    assert!(!run.is_open());
    run_join(&mut run, &mut storage, &bodies, FIRST, 0, message.len());
    let (joined, next) = run.finish(&storage).expect("finished");
    assert_eq!(joined, &message[..]);
    assert_eq!(next, FIRST.wrapping_add(bodies.len() as u32));
    assert!(!run.is_open());
}

#[test]
fn two_runs_hold_two_messages_in_two_storages_at_once() {
    let (first_message, first_bodies) = fragments(5000, FIRST);
    let (second_message, second_bodies) = fragments(3000, 9000);
    let mut a = std::vec![0u8; first_message.len()];
    let mut b = std::vec![0u8; second_message.len()];
    let (mut run_a, mut run_b) = (Run::new(), Run::new());
    // The fragments of the two messages arrive interleaved, each into its own storage.
    let mut pairs = first_bodies.iter().zip(second_bodies.iter());
    for (x, y) in pairs.by_ref() {
        let fx = decode_fragment(x, Some(BATCH)).expect("fragment");
        let fy = decode_fragment(y, Some(BATCH)).expect("fragment");
        run_a
            .accept(&fx, &mut a, FIRST, 0, TIMEOUT, 6000)
            .expect("a");
        run_b
            .accept(&fy, &mut b, 9000, 0, TIMEOUT, 6000)
            .expect("b");
    }
    for rest in first_bodies.iter().skip(second_bodies.len()) {
        let fragment = decode_fragment(rest, Some(BATCH)).expect("fragment");
        run_a
            .accept(&fragment, &mut a, FIRST, 0, TIMEOUT, 6000)
            .expect("a");
    }
    assert_eq!(run_a.finish(&a).expect("a done").0, &first_message[..]);
    assert_eq!(run_b.finish(&b).expect("b done").0, &second_message[..]);
}

#[test]
fn a_run_takes_its_deadline_and_its_limit_from_the_caller() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let mut run = Run::new();
    let first = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
    run.accept(&first, &mut storage, FIRST, 100, TIMEOUT, message.len())
        .expect("first");
    // The same run is late for a shorter timeout and in time for a longer one.
    assert_eq!(run.deadline(TIMEOUT), Some(100 + TIMEOUT));
    assert_eq!(run.deadline(1), Some(101));
    assert!(!run.expired(100 + TIMEOUT, TIMEOUT));
    assert!(run.expired(100 + TIMEOUT + 1, TIMEOUT));
    assert!(run.expired(102, 1));
    // A limit one byte under the message refuses it, whatever the storage holds.
    let mut other = Run::new();
    let mut again = std::vec![0u8; message.len()];
    let result = bodies.iter().try_for_each(|body| {
        let fragment = decode_fragment(body, Some(BATCH)).expect("fragment");
        other
            .accept(&fragment, &mut again, FIRST, 0, TIMEOUT, message.len() - 1)
            .map(|_| ())
    });
    assert_eq!(
        result,
        Err(FragmentError::Refused(
            crate::zenoh_profile0::Refusal::OverBound
        ))
    );
    assert!(!other.is_open());
}

#[test]
fn a_run_that_is_not_open_has_no_deadline_and_finishes_nothing() {
    let run = Run::new();
    assert_eq!(run.deadline(TIMEOUT), None);
    assert!(!run.expired(u64::MAX, TIMEOUT));
    let mut run = Run::new();
    assert_eq!(run.finish(&[]).err(), Some(FragmentError::FragmentSequence));
}

#[test]
fn a_run_measures_its_deadline_from_its_first_fragment_and_never_refreshes_it() {
    let (message, bodies) = fragments(5000, FIRST);
    assert!(bodies.len() >= 3);
    let mut storage = std::vec![0u8; message.len()];
    let mut run = Run::new();
    let take = |run: &mut Run, storage: &mut [u8], at: usize, now: u64, timeout: u64| {
        let fragment = decode_fragment(&bodies[at], Some(BATCH)).expect("fragment");
        run.accept(&fragment, storage, FIRST, now, timeout, message.len())
    };
    take(&mut run, &mut storage, 0, 1000, 700).expect("first");
    // A continuation 600 ms later is in time and must not move the deadline.
    take(&mut run, &mut storage, 1, 1600, 700).expect("second");
    assert_eq!(run.deadline(700), Some(1700));
    // 101 ms after the second fragment is 701 ms after the first: late, though under 700 ms from the second.
    assert_eq!(
        take(&mut run, &mut storage, 2, 1701, 700),
        Err(FragmentError::ReassemblyTimeout)
    );
    assert!(!run.is_open());
}

#[test]
fn a_run_takes_its_timeout_from_the_call_and_holds_none_of_its_own() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    // Two timeouts that no constant can both equal: the same run is in time under the longer and late under the
    // shorter, in the same state.
    // The second fragment arrives 9000 ms after the first. A timeout of 8000 refuses it, and one of 10000 takes
    // it, so a fixed value under 9000 refuses the second case and one over 9000 takes the first.
    for (timeout, late) in [
        (100u64, true),
        (8_000, true),
        (10_000, false),
        (60_000, false),
    ] {
        let mut run = Run::new();
        let first = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
        run.accept(&first, &mut storage, FIRST, 0, timeout, message.len())
            .expect("first");
        let second = decode_fragment(&bodies[1], Some(BATCH)).expect("fragment");
        // `expired` is read before the fragment arrives: a late fragment is refused and releases the run.
        assert_eq!(run.expired(9000, timeout), late, "timeout {timeout}");
        let result = run.accept(&second, &mut storage, FIRST, 9000, timeout, message.len());
        assert_eq!(result.is_err(), late, "timeout {timeout}");
        assert_eq!(run.is_open(), !late, "timeout {timeout}");
    }
}

#[test]
fn the_first_fragment_of_a_run_must_carry_the_number_it_is_given() {
    let (message, bodies) = fragments(5000, FIRST);
    let mut storage = std::vec![0u8; message.len()];
    let fragment = decode_fragment(&bodies[0], Some(BATCH)).expect("fragment");
    for expected in [FIRST - 1, FIRST + 1, 0, u32::MAX] {
        let mut run = Run::new();
        assert_eq!(
            run.accept(&fragment, &mut storage, expected, 0, TIMEOUT, message.len()),
            Err(FragmentError::SequenceMismatch),
            "expected {expected}"
        );
        assert!(!run.is_open());
    }
    let mut run = Run::new();
    assert!(
        run.accept(&fragment, &mut storage, FIRST, 0, TIMEOUT, message.len())
            .is_ok()
    );
    // A continuation is held to its predecessor and not to the number the first one was given.
    let skipped = decode_fragment(&bodies[2], Some(BATCH)).expect("fragment");
    assert_eq!(
        run.accept(&skipped, &mut storage, 0, 1, TIMEOUT, message.len()),
        Err(FragmentError::FragmentSequence)
    );
}
