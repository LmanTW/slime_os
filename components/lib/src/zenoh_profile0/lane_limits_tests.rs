//! Host tests for the lane configuration: the boundaries `contracts/zenoh-link-limits/v2` states, each on both
//! sides, and the sizes the contract's two margins must cover.

use super::*;
use crate::zenoh_profile0::limits::{DEMO, HEAP, LARGE};
use crate::zenoh_profile0::reassembly::Run;

fn exact(base: Limits, runs: usize) -> LaneLimits {
    let mut lanes = heap(base, runs);
    lanes.limits.stack_bytes = lanes.required_stack();
    lanes.limits.heap_bytes = lanes.heap_needed();
    lanes
}

#[test]
fn the_pinned_figures_are_the_arithmetic() {
    for (runs, stack, heap_bytes) in [
        (1, 18_504, 149_004),
        (2, 18_632, 165_560),
        (16, 19_528, 397_344),
    ] {
        let lanes = exact(HEAP, runs);
        assert_eq!(lanes.required_stack(), stack, "stack of {runs} runs");
        assert_eq!(lanes.heap_needed(), heap_bytes, "heap of {runs} runs");
        assert_eq!(lanes.check(), Ok(()), "{runs} runs");
    }
}

#[test]
fn one_run_is_the_version_one_configuration() {
    let lanes = heap(HEAP, 1);
    assert_eq!(lanes.lane_bytes(), 0);
    assert_eq!(lanes.required_stack(), HEAP.required_stack());
    assert_eq!(lanes.heap_needed(), HEAP.heap_needed());
    assert_eq!(lanes.check(), Ok(()));
    assert_eq!(fixed(DEMO).check(), Ok(()));
    assert_eq!(fixed(LARGE).check(), Ok(()));
}

#[test]
fn the_run_count_is_one_to_sixteen_for_a_heap_link() {
    assert_eq!(exact(HEAP, 16).check(), Ok(()));
    assert_eq!(exact(HEAP, 17).check(), Err(LimitsError::Count));
    assert_eq!(heap(HEAP, 0).check(), Err(LimitsError::Heap));
}

#[test]
fn a_fixed_link_holds_no_run() {
    for runs in [1, 2, 16] {
        let lanes = LaneLimits {
            limits: LARGE,
            max_runs: runs,
        };
        assert_eq!(lanes.check(), Err(LimitsError::Fixed), "{runs} runs");
    }
    assert_eq!(
        LaneLimits {
            limits: DEMO,
            max_runs: 17
        }
        .check(),
        Err(LimitsError::Count)
    );
}

#[test]
fn a_count_far_past_the_limit_is_refused_before_any_sum() {
    for runs in [17, 1 << 40, 1 << 57, 1 << 58, 1 << 62, usize::MAX] {
        for base in [HEAP, LARGE] {
            let lanes = LaneLimits {
                limits: base,
                max_runs: runs,
            };
            assert_eq!(lanes.check(), Err(LimitsError::Count), "{runs} runs");
        }
    }
}

#[test]
fn the_stack_and_the_heap_must_cover_the_runs_to_the_byte() {
    let lanes = exact(HEAP, 2);
    let mut short_stack = lanes;
    short_stack.limits.stack_bytes -= 1;
    assert_eq!(short_stack.check(), Err(LimitsError::Stack));
    let mut short_heap = lanes;
    short_heap.limits.heap_bytes -= 1;
    assert_eq!(short_heap.check(), Err(LimitsError::Heap));
    let mut one_run_heap = lanes;
    one_run_heap.limits.heap_bytes = heap(HEAP, 1).heap_needed();
    assert_eq!(one_run_heap.check(), Err(LimitsError::Heap));
    let mut one_run_stack = lanes;
    one_run_stack.limits.stack_bytes = HEAP.required_stack();
    assert_eq!(one_run_stack.check(), Err(LimitsError::Stack));
}

#[test]
fn one_outstanding_sample_and_two_runs_need_four_messages_of_heap() {
    let mut base = HEAP;
    base.outstanding_samples = 1;
    let lanes = exact(base, 2);
    assert_eq!(lanes.heap_needed(), 4 * base.message_bytes());
    assert_eq!(lanes.check(), Ok(()));
    let mut short = lanes;
    short.limits.heap_bytes = 3 * base.message_bytes();
    assert_eq!(short.check(), Err(LimitsError::Heap));
}

#[test]
fn a_declaration_the_version_one_rules_refuse_is_refused_here() {
    let mut lanes = exact(HEAP, 2);
    lanes.limits.batch_bytes = 0;
    assert_eq!(lanes.check(), Err(LimitsError::Batch));
    let mut lanes = exact(HEAP, 2);
    lanes.limits.reassembly_timeout_ms = 0;
    assert_eq!(lanes.check(), Err(LimitsError::Heap));
    let mut lanes = exact(HEAP, 2);
    lanes.limits.outstanding_samples = 0;
    assert_eq!(lanes.check(), Err(LimitsError::Count));
}

#[test]
fn the_margins_cover_the_state_a_run_and_the_lanes_hold() {
    // A slot of the session's table holds a `Run` and the `Lane` it serves. The contract charges 64 bytes for each
    // run beyond the first, so a slot, and the growth of the session for one more run, must fit it.
    let slot = (core::mem::size_of::<Run>()
        + core::mem::size_of::<crate::zenoh_profile0::lane::Lane>()) as u64;
    assert!(slot <= RUN_OVERHEAD_BYTES, "a slot is {slot} bytes");
    type Held<const R: usize> = crate::zenoh_profile0::session::SessionOf<1, 2, 129, 4, R>;
    // The table is part of the session, and padding may round a step, so the check is on the steps and on the
    // whole growth from 2 runs to 16, which must stay within the 14 runs the contract charges for.
    let step = (core::mem::size_of::<Held<3>>() - core::mem::size_of::<Held<2>>()) as u64;
    assert!(
        (1..=RUN_OVERHEAD_BYTES).contains(&step),
        "a run adds {step} bytes to a session"
    );
    let grown = (core::mem::size_of::<Held<16>>() - core::mem::size_of::<Held<2>>()) as u64;
    assert!(
        grown <= 14 * RUN_OVERHEAD_BYTES,
        "14 runs add {grown} bytes to a session"
    );
    // The counters are one 32-bit sequence number for each of the 16 lanes, which is all the contract charges.
    assert_eq!(
        (MAX_RUNS_LIMIT * core::mem::size_of::<u32>()) as u64,
        LANE_COUNTER_BYTES
    );
}

#[test]
fn a_link_with_several_runs_holds_its_batch_to_the_qos_init_ack() {
    let batch = |runs: usize, bytes: usize| {
        let mut base = HEAP;
        base.batch_bytes = bytes;
        base.key_bytes = 1;
        exact(base, runs)
    };
    // 87 bytes for the largest INIT_ACK, one for the extension and two for the stream length.
    assert_eq!(batch(2, 89).check(), Err(LimitsError::Batch));
    assert_eq!(batch(2, 90).check(), Ok(()));
    assert_eq!(batch(16, 89).check(), Err(LimitsError::Batch));
    assert_eq!(batch(16, 90).check(), Ok(()));
    // A link with one run writes no extension and keeps the version 1 floor.
    assert_eq!(batch(1, 89).check(), Ok(()));
    assert_eq!(batch(1, 88).check(), Err(LimitsError::Batch));
}
