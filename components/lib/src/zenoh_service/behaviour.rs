//! What the core does that the exam's pinned transcript does not show. Each test fails against the
//! mistake it names, so the claim in the core's documentation is checked and not only written.

use super::exam::{Exam, GID, KEYS, open, params, rows};
use super::{Core, Item, Row, ServiceError};
use crate::zenoh_profile0::session::{Config, Params, Role, SessionError, SessionOf};
use crate::zenoh_profile0::{MAX_BATCH_BYTES, MAX_KEY_BYTES};

#[test]
fn a_publication_on_a_session_that_is_not_open_is_not_open_and_not_unsubscribed() {
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let config = Config {
        zid: &[0xb2; 8],
        lease_ms: 10_000,
        initial_sn: 7000,
        cookie: &[0xc0; 32],
    };
    let mut idle =
        SessionOf::<1, 5, MAX_KEY_BYTES, 4>::with_params(Role::Listener, &config, params())
            .expect("idle");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let refused = core.publish(&mut idle, 0, KEYS[0], 1, 1, &[1, 2, 3], &mut out);
    assert_eq!(
        refused.err(),
        Some(ServiceError::Session(SessionError::NotOpen))
    );
    assert_eq!(
        core.held(0).unwrap(),
        (0, 0),
        "a refused publication reaches no ring"
    );
    assert_eq!(core.held(1).unwrap(), (0, 0));
}

#[test]
fn a_session_declared_with_other_parameters_is_refused_before_anything_changes() {
    let (mut service, _peer) = open();
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    // The same table size, so the type is the same, with a different count on each side.
    let config = Config {
        zid: &[0xb2; 8],
        lease_ms: 10_000,
        initial_sn: 7000,
        cookie: &[0xc0; 32],
    };
    let other = Params {
        local: 4,
        per_side: 1,
        ..params()
    };
    let mut different =
        SessionOf::<1, 5, MAX_KEY_BYTES, 4>::with_params(Role::Listener, &config, other)
            .expect("different");
    let mut out = [0u8; MAX_BATCH_BYTES];
    assert_eq!(
        core.declare_next(&mut different, &mut out).err(),
        Some(ServiceError::WrongSession)
    );
    assert_eq!(
        core.publish(&mut different, 0, KEYS[0], 1, 1, &[1, 2, 3], &mut out)
            .err(),
        Some(ServiceError::WrongSession)
    );
    assert_eq!(
        core.on_batch(&mut different, &[0x01], 1, &mut out).err(),
        Some(ServiceError::WrongSession)
    );
    assert_eq!(core.declared(), 0, "a refused declaration declares nothing");
    // The session the core was declared with still works.
    assert!(
        core.declare_next(&mut service, &mut out)
            .expect("declares")
            .is_some()
    );
}

#[test]
fn a_row_with_an_empty_key_or_a_key_over_the_session_bound_is_invalid() {
    let honest = rows();
    let mut empty = honest;
    empty[0] = Row {
        key: "",
        ..honest[0]
    };
    assert_eq!(
        Exam::new(&empty, GID, &params()).err(),
        Some(ServiceError::InvalidGrants)
    );
    let long = "k".repeat(MAX_KEY_BYTES + 1);
    let mut over = honest;
    over[0] = Row {
        key: &long,
        ..honest[0]
    };
    assert_eq!(
        Exam::new(&over, GID, &params()).err(),
        Some(ServiceError::InvalidGrants)
    );
    let exact = "k".repeat(MAX_KEY_BYTES);
    let mut at_bound = honest;
    at_bound[0] = Row {
        key: &exact,
        ..honest[0]
    };
    assert!(
        Exam::new(&at_bound, GID, &params()).is_ok(),
        "a key of exactly the bound is valid"
    );
}

#[test]
fn a_session_that_reassembles_fragments_is_refused() {
    let heap = Params {
        fragments: true,
        ..params()
    };
    assert_eq!(
        Exam::new(&rows(), GID, &heap).err(),
        Some(ServiceError::InvalidGrants)
    );
    let _ = Core::<3, 4, 12, 5>::sizes();
}

/// Feeds the core one Put from the peer on `key`, written at the sequence number the service expects.
fn peer_put(
    core: &mut Exam<'_>,
    service: &mut super::exam::Svc,
    key: usize,
    sequence: i64,
    timestamp: i64,
) {
    let attachment =
        crate::zenoh_profile0::encode::attachment(sequence, timestamp, &GID).expect("attachment");
    let mut buf = [0u8; MAX_BATCH_BYTES];
    let mut frame =
        crate::zenoh_profile0::encode::FrameEncoder::new(&mut buf, service.expected_rx_sn())
            .expect("frame");
    frame
        .push_put(
            crate::zenoh_profile0::Mapping::Receiver,
            KEYS[key],
            &attachment,
            &[sequence as u8, 2, 3],
        )
        .expect("put");
    let length = frame.finish().expect("finish");
    let body = buf[..length].to_vec();
    let mut out = [0u8; MAX_BATCH_BYTES];
    core.on_batch(service, &body, 40, &mut out)
        .expect("a Put to a subscribed key");
}

#[test]
fn a_holder_that_subscribes_to_two_keys_tells_their_samples_apart() {
    // Holder a subscribes to k1 (subscription 1) and k2 (subscription 2).
    let (mut service, _peer) = open();
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let mut out = [0u8; MAX_BATCH_BYTES];
    while core
        .declare_next(&mut service, &mut out)
        .expect("declares")
        .is_some()
    {}
    peer_put(&mut core, &mut service, 0, 5, 4005);
    peer_put(&mut core, &mut service, 1, 6, 4006);
    let Some(Item::Sample(first)) = core.take(0).unwrap() else {
        panic!("a sample")
    };
    let Some(Item::Sample(second)) = core.take(0).unwrap() else {
        panic!("a sample")
    };
    assert_eq!(
        (first.subscription, first.sequence, first.timestamp),
        (1, 5, 4005)
    );
    assert_eq!(
        (second.subscription, second.sequence, second.timestamp),
        (2, 6, 4006)
    );
}

#[test]
fn a_local_publication_carries_the_subscription_of_the_key_and_the_timestamp_it_was_given() {
    let (mut service, _peer) = open();
    let mut core = Exam::new(&rows(), GID, &params()).expect("the honest grants");
    let mut out = [0u8; MAX_BATCH_BYTES];
    while core
        .declare_next(&mut service, &mut out)
        .expect("declares")
        .is_some()
    {}
    core.publish(&mut service, 0, KEYS[0], 9, 7777, &[9, 2, 3], &mut out)
        .expect("a granted publication");
    let Some(Item::Sample(on_a)) = core.take(0).unwrap() else {
        panic!("a sample")
    };
    let Some(Item::Sample(on_b)) = core.take(1).unwrap() else {
        panic!("a sample")
    };
    assert_eq!((on_a.subscription, on_a.timestamp), (1, 7777));
    assert_eq!(
        (on_b.subscription, on_b.timestamp),
        (1, 7777),
        "b subscribes to the same key, so the same subscription"
    );
}

#[test]
fn a_table_with_fewer_rows_than_the_ceiling_is_served() {
    // The core is built for five rows. A table of three is served, and the two slots it does not use belong to no holder.
    let three = &rows()[..3];
    let core = Exam::new(three, GID, &params()).expect("a table below the ceiling");
    assert_eq!(core.row_count(0), 2);
    assert_eq!(core.row_count(1), 1);
    assert_eq!(core.row_count(2), 0, "a holder with no row has none");
    assert!(core.row_key(0, 1).is_some());
    assert!(
        core.row_key(0, 2).is_none(),
        "an empty slot is not a row of holder 0"
    );
    assert!(core.row_key(1, 1).is_none());
    // More rows than the ceiling are still refused, and so are none.
    let mut six = rows().to_vec();
    six.push(rows()[0]);
    assert_eq!(
        Exam::new(&six, GID, &params()).err(),
        Some(ServiceError::InvalidGrants)
    );
    assert_eq!(
        Exam::new(&[], GID, &params()).err(),
        Some(ServiceError::InvalidGrants)
    );
}
