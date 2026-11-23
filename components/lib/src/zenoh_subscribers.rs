//! The subscribers exam: a Profile 0 session that holds several subscriptions of its own.
//!
//! `Params::local` says how many subscriptions this side may declare, and the subscriber table holds
//! `per_side + local` slots. This module drives a listener that declares three and a connector that
//! receives them, and prints one `[zenoh-exam] subscribers ...` line for each scenario, frame, count,
//! sample and refusal. `scripts/check/check-zenoh-profile0.py --slice subscribers` owns what those lines
//! must be, and `scripts/lib/zenoh_subscribers_exam.py` the bytes and the classes.

use crate::zenoh_profile0::encode::{self, FrameEncoder};
use crate::zenoh_profile0::session::{
    Config, Event, Outcome, Params, Role, SessionError, SessionOf, State,
};
use crate::zenoh_profile0::{MAX_BATCH_BYTES, MAX_KEY_BYTES, Mapping, StreamFramer};
use std::vec::Vec;

/// A session whose table holds `S` subscriptions. The usual pair takes three of one side and one of the
/// other, which is four slots.
type Sized<const S: usize> = SessionOf<1, S, MAX_KEY_BYTES, 4>;
type Own = Sized<4>;

const LISTENER_SN: u32 = 7000;
const CONNECTOR_SN: u32 = 9000;
const LEASE_MS: u64 = 10_000;
const KEYS: [&str; 4] = [
    "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b",
    "0/slime_demo/extra/second",
    "0/slime_demo/extra/third",
    "0/slime_demo/extra/fourth",
];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];

fn line(kind: &str, text: &str) {
    println!("[zenoh-exam] subscribers {kind} {text}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The parameters of a side that may declare `local` subscriptions and takes `per_side` of the peer's.
fn params(local: usize, per_side: usize) -> Params {
    Params {
        local,
        per_side,
        events: 4,
        ..Params::DEMO
    }
}

fn listener_config() -> Config<'static> {
    Config {
        zid: &[0xb2; 8],
        lease_ms: LEASE_MS,
        initial_sn: LISTENER_SN,
        cookie: &[0xc0; 32],
    }
}

fn connector_config() -> Config<'static> {
    Config {
        zid: &[0xa1; 8],
        lease_ms: LEASE_MS,
        initial_sn: CONNECTOR_SN,
        cookie: &[],
    }
}

/// What a batch raised, owned so it outlives the buffer.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Handshake,
    Declared(u32),
    Sample(i64),
    Undeclared(u32),
    Closed,
}

fn owned(outcome: &Outcome<'_, 4>) -> Vec<Ev> {
    outcome
        .events
        .iter()
        .map(|event| match *event {
            Event::HandshakeComplete => Ev::Handshake,
            Event::SubscriberDeclared { id } => Ev::Declared(id),
            Event::SampleDelivered { sequence, .. } => Ev::Sample(sequence),
            Event::SubscriberUndeclared { id } => Ev::Undeclared(id),
            Event::Closed { .. } => Ev::Closed,
            Event::SampleStored { .. } => panic!("a session that cannot fragment stores no sample"),
            Event::Dropped { .. } => panic!("a session with one run drops nothing"),
        })
        .collect()
}

/// A batch carried over a byte stream and read back, so the exam sees what a link would deliver.
fn through_stream(batch: &[u8]) -> Vec<u8> {
    let mut wire = [0u8; MAX_BATCH_BYTES + 2];
    let total = encode::stream_batch(&mut wire, batch).expect("stream");
    let mut framer = StreamFramer::new();
    assert_eq!(framer.push(&wire[..total]), total);
    framer
        .peek_batch()
        .expect("prefix")
        .expect("complete")
        .to_vec()
}

/// Feeds `batch` to `session`; returns what it sent and the events it raised.
fn feed<const S: usize>(
    session: &mut Sized<S>,
    batch: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<Ev>), SessionError> {
    let body = through_stream(batch);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(&body, now_ms, &mut out)?;
    Ok((outcome.batch(&out).to_vec(), owned(&outcome)))
}

fn feed_ok<const S: usize>(
    session: &mut Sized<S>,
    batch: &[u8],
    now_ms: u64,
) -> (Vec<u8>, Vec<Ev>) {
    feed(session, batch, now_ms).expect("the session takes the batch")
}

/// Opens a listener over `L` slots and a connector over `C` slots, each declared by its own parameters.
fn open_sized<const L: usize, const C: usize>(
    listener: Params,
    connector: Params,
) -> (Sized<C>, Sized<L>) {
    let mut a = Sized::<C>::with_params(Role::Connector, &connector_config(), connector)
        .expect("connector");
    let mut b =
        Sized::<L>::with_params(Role::Listener, &listener_config(), listener).expect("listener");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let syn = a.connect(0, &mut out).expect("connect");
    let init_syn = syn.batch(&out).to_vec();
    let (init_ack, _) = feed_ok(&mut b, &init_syn, 1);
    let (open_syn, _) = feed_ok(&mut a, &init_ack, 2);
    let (open_ack, events) = feed_ok(&mut b, &open_syn, 3);
    assert_eq!(events, [Ev::Handshake]);
    let (_, events) = feed_ok(&mut a, &open_ack, 4);
    assert_eq!(events, [Ev::Handshake]);
    assert!(a.is_open() && b.is_open());
    (a, b)
}

fn open(listener: Params, connector: Params) -> (Own, Own) {
    open_sized::<4, 4>(listener, connector)
}

/// The usual pair: the listener declares up to three, the connector takes up to three of them.
fn pair() -> (Own, Own) {
    open(params(3, 1), params(1, 3))
}

fn sent<const S: usize>(
    session: &mut Sized<S>,
    build: impl FnOnce(&mut Sized<S>, &mut [u8]) -> Result<Outcome<'static, 4>, SessionError>,
) -> Result<Vec<u8>, SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = build(session, &mut out)?;
    Ok(outcome.batch(&out).to_vec())
}

/// `b` declares subscriber `id` on `KEYS[at]`, and `a` takes the frame.
fn declare<const A: usize, const B: usize>(
    a: &mut Sized<A>,
    b: &mut Sized<B>,
    id: u32,
    at: usize,
    now_ms: u64,
) -> Vec<u8> {
    let frame = sent(b, |session, out| {
        session.send_declare_subscriber(id, KEYS[at], out)
    })
    .expect("declaration");
    let (reply, events) = feed_ok(a, &frame, now_ms);
    assert!(reply.is_empty());
    assert_eq!(events, [Ev::Declared(id)]);
    frame
}

fn undeclare<const A: usize, const B: usize>(
    a: &mut Sized<A>,
    b: &mut Sized<B>,
    id: u32,
    at: usize,
    now_ms: u64,
) -> Vec<u8> {
    let frame = sent(b, |session, out| {
        session.send_undeclare_subscriber(id, KEYS[at], out)
    })
    .expect("undeclaration");
    let (reply, events) = feed_ok(a, &frame, now_ms);
    assert!(reply.is_empty());
    assert_eq!(events, [Ev::Undeclared(id)]);
    frame
}

/// A FRAME carrying one Put to `key`, at the sequence number the listener expects next.
fn put(sn: u32, key: &str, sequence: i64) -> Vec<u8> {
    let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut out, sn).expect("frame");
    frame
        .push_put(Mapping::Receiver, key, &attachment, &[1, 2, 3])
        .expect("put");
    let length = frame.finish().expect("finish");
    out[..length].to_vec()
}

/// Sends a Put from `from` to a key its peer declared, and returns the batch.
fn send_put<const S: usize>(
    from: &mut Sized<S>,
    key: &str,
    sequence: i64,
) -> Result<Vec<u8>, SessionError> {
    let attachment = encode::attachment(sequence, 1000 + sequence, &GID).expect("attachment");
    sent(from, |session, out| {
        session.send_put(key, &attachment, &[1, 2, 3], out)
    })
}

/// The connector sends a Put to the listener, and the listener's events come back.
fn deliver<const A: usize, const B: usize>(
    connector: &mut Sized<A>,
    listener: &mut Sized<B>,
    key: &str,
    sequence: i64,
    now_ms: u64,
) -> Result<Vec<Ev>, SessionError> {
    let frame = send_put(connector, key, sequence)?;
    Ok(feed(listener, &frame, now_ms)?.1)
}

/// How many subscriptions each side holds. Each side counts both directions.
fn held<const A: usize, const B: usize>(label: &str, declaring: &Sized<A>, receiving: &Sized<B>) {
    line(
        "held",
        &format!(
            "{label} {} {}",
            declaring.subscribers(),
            receiving.subscribers()
        ),
    );
}

fn class(error: SessionError) -> &'static str {
    match error {
        SessionError::SubscriberLimit => "subscriber-limit",
        SessionError::UndeclaredKey => "undeclared-key",
        SessionError::UnknownSubscriber => "unknown-subscriber",
        SessionError::InvalidConfig => "invalid-config",
        SessionError::NotOpen => "not-open",
        SessionError::Decode(refusal) => refusal.name(),
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

/// The refusals seen so far, by name and class. The exam lists them in its own order, so they are printed
/// together at the end and not where each scenario meets them.
type Refusals = Vec<(String, &'static str)>;

fn refused(seen: &mut Refusals, name: &str, result: Result<(), SessionError>) {
    let error = result.expect_err(name);
    seen.push((name.to_string(), class(error)));
}

fn expect_sample(events: Result<Vec<Ev>, SessionError>, label: &str, sequence: i64) {
    assert_eq!(events.expect(label), [Ev::Sample(sequence)], "{label}");
    line("delivered", &format!("{label} {sequence}"));
}

/// The refusal of a declaration, an undeclaration or a Put, by name.
fn refuse(seen: &mut Refusals, name: &str, outcome: Result<Vec<u8>, SessionError>) {
    refused(seen, name, outcome.map(|_| ()));
}

fn refuse_events(seen: &mut Refusals, name: &str, outcome: Result<Vec<Ev>, SessionError>) {
    refused(seen, name, outcome.map(|_| ()));
}

/// The refusals the exam lists, in its order, each with the class the session gave it.
const REFUSAL_ORDER: [&str; 13] = [
    "fourth-own-subscriber",
    "own-subscriber-repeated-id",
    "put-to-undeclared-key-sent",
    "put-to-undeclared-key-received",
    "undeclare-unknown-id",
    "undeclare-held-id-on-another-key",
    "put-after-every-subscription-on-a-key-undeclared",
    "peer-declaration-over-its-limit",
    "no-own-subscriber-configured",
    "table-smaller-than-both-sides",
    "table-larger-than-both-sides",
    "own-subscriber-before-open",
    "demo-params-second-own-subscriber",
];

fn print_refusals(seen: &Refusals) {
    assert_eq!(
        seen.len(),
        REFUSAL_ORDER.len(),
        "every refusal scenario ran exactly once"
    );
    for name in REFUSAL_ORDER {
        let (_, class) = seen
            .iter()
            .find(|(seen_name, _)| seen_name == name)
            .unwrap_or_else(|| panic!("{name} did not run"));
        line("refused", &format!("{name} {class}"));
    }
}

fn declare_frame<const S: usize>(
    listener: &mut Sized<S>,
    id: u32,
    at: usize,
) -> Result<Vec<u8>, SessionError> {
    sent(listener, |session, out| {
        session.send_declare_subscriber(id, KEYS[at], out)
    })
}

fn undeclare_frame<const S: usize>(
    listener: &mut Sized<S>,
    id: u32,
    at: usize,
) -> Result<Vec<u8>, SessionError> {
    sent(listener, |session, out| {
        session.send_undeclare_subscriber(id, KEYS[at], out)
    })
}

#[test]
fn the_subscribers_exam() {
    let mut seen = Refusals::new();
    let mut now = 10;
    let mut tick = || {
        now += 1;
        now
    };

    // One: three declarations, and the frames the host reference reproduces.
    let (mut connector, mut listener) = pair();
    for id in 1..=3u32 {
        let frame = declare(&mut connector, &mut listener, id, id as usize - 1, tick());
        line("frame", &format!("declare-{id} {}", hex(&frame)));
    }
    held("declared-three", &listener, &connector);
    line("ok", "declare-several-own-subscribers");

    // Two: a Put to each declared key is delivered once with its sequence.
    for (label, at, sequence) in [
        ("every-key-1", 0, 0),
        ("every-key-2", 1, 1),
        ("every-key-3", 2, 2),
    ] {
        expect_sample(
            deliver(&mut connector, &mut listener, KEYS[at], sequence, tick()),
            label,
            sequence,
        );
    }
    line("ok", "put-reaches-every-declared-key");

    // The sender refuses a Put to a key the peer never declared, and the receiver one to a key none of its
    // own subscriptions holds.
    refuse(
        &mut seen,
        "put-to-undeclared-key-sent",
        send_put(&mut connector, KEYS[3], 99),
    );
    let stray = put(connector.next_tx_sn(), KEYS[3], 99);
    refuse_events(
        &mut seen,
        "put-to-undeclared-key-received",
        feed(&mut listener, &stray, tick()).map(|(_, events)| events),
    );

    // Three: undeclaring one subscription keeps the others, and an unknown id or a wrong key is refused.
    let frame = undeclare(&mut connector, &mut listener, 2, 1, tick());
    line("frame", &format!("undeclare-2 {}", hex(&frame)));
    held("undeclared-one", &listener, &connector);
    for (label, at, sequence) in [("kept-key-1", 0, 10), ("kept-key-3", 2, 11)] {
        expect_sample(
            deliver(&mut connector, &mut listener, KEYS[at], sequence, tick()),
            label,
            sequence,
        );
    }
    refuse(
        &mut seen,
        "undeclare-unknown-id",
        undeclare_frame(&mut listener, 9, 0),
    );
    refuse(
        &mut seen,
        "undeclare-held-id-on-another-key",
        undeclare_frame(&mut listener, 1, 1),
    );
    refuse(
        &mut seen,
        "put-after-every-subscription-on-a-key-undeclared",
        send_put(&mut connector, KEYS[1], 98),
    );
    line("ok", "undeclare-one-keeps-the-others");

    // Four: the slot an undeclaration freed takes a fourth key, and that key delivers.
    declare(&mut connector, &mut listener, 4, 3, tick());
    held("reused-slot", &listener, &connector);
    expect_sample(
        deliver(&mut connector, &mut listener, KEYS[3], 20, tick()),
        "reused-key-4",
        20,
    );
    line("ok", "slot-freed-by-undeclare-is-reusable");

    // The limit: a fourth own subscription is at the limit.
    refuse(
        &mut seen,
        "fourth-own-subscriber",
        declare_frame(&mut listener, 5, 1),
    );
    // A held id again is refused while a slot is still free, so only the duplicate check can refuse it. With
    // every own slot taken, the quota check would refuse it first and this scenario would show nothing.
    let (mut spare_connector, mut spare_listener) = open(params(3, 1), params(1, 3));
    declare(&mut spare_connector, &mut spare_listener, 1, 0, tick());
    declare(&mut spare_connector, &mut spare_listener, 3, 2, tick());
    assert_eq!(
        spare_listener.subscribers(),
        2,
        "one own slot is still free"
    );
    let next_sn = spare_listener.next_tx_sn();
    refuse(
        &mut seen,
        "own-subscriber-repeated-id",
        declare_frame(&mut spare_listener, 1, 1),
    );
    assert_eq!(
        spare_listener.next_tx_sn(),
        next_sn,
        "a refused declaration spends no sequence number"
    );

    // Five: two subscriptions on one key deliver once, and one is still left after the other goes.
    let (mut connector, mut listener) = open(params(3, 1), params(1, 3));
    declare(&mut connector, &mut listener, 1, 0, tick());
    declare(&mut connector, &mut listener, 2, 0, tick());
    expect_sample(
        deliver(&mut connector, &mut listener, KEYS[0], 30, tick()),
        "two-on-one-key",
        30,
    );
    undeclare(&mut connector, &mut listener, 1, 0, tick());
    expect_sample(
        deliver(&mut connector, &mut listener, KEYS[0], 31, tick()),
        "one-of-two-left",
        31,
    );
    line("ok", "two-subscriptions-on-one-key-deliver-once");

    // Six: closing releases every subscription on both counts.
    declare(&mut connector, &mut listener, 3, 2, tick());
    let mut out = [0u8; MAX_BATCH_BYTES];
    let close = listener.close(0, &mut out).expect("close");
    let batch = close.batch(&out).to_vec();
    let (_, events) = feed_ok(&mut connector, &batch, tick());
    assert_eq!(events, [Ev::Closed]);
    assert_eq!(listener.state(), State::Closed);
    assert_eq!(connector.state(), State::Closed);
    held("closed", &listener, &connector);
    line("ok", "close-releases-every-subscription");

    // The peer's limit: a peer that declares past its own limit is refused. The listener may declare two and
    // takes one, so its table has three slots. The connector takes one and holds one, so it has two. The
    // connector takes the first declaration and refuses the second.
    let (mut connector, mut listener) = open_sized::<3, 2>(params(2, 1), params(1, 1));
    declare(&mut connector, &mut listener, 1, 0, tick());
    let over = declare_frame(&mut listener, 2, 1).expect("the declaring side has room");
    refuse_events(
        &mut seen,
        "peer-declaration-over-its-limit",
        feed(&mut connector, &over, tick()).map(|(_, events)| events),
    );

    // The parameters have to add up.
    refused(
        &mut seen,
        "no-own-subscriber-configured",
        // Three slots for a peer that may declare three and a side that may declare none, so the size adds
        // up and only the minimum of one own subscription can refuse it.
        Sized::<3>::with_params(Role::Listener, &listener_config(), params(0, 3)).map(|_| ()),
    );
    refused(
        &mut seen,
        "table-smaller-than-both-sides",
        Own::with_params(Role::Listener, &listener_config(), params(2, 1)).map(|_| ()),
    );
    refused(
        &mut seen,
        "table-larger-than-both-sides",
        Own::with_params(Role::Listener, &listener_config(), params(3, 3)).map(|_| ()),
    );

    // A declaration before the session is open is refused.
    let mut idle =
        Own::with_params(Role::Listener, &listener_config(), params(3, 1)).expect("listener");
    refuse(
        &mut seen,
        "own-subscriber-before-open",
        declare_frame(&mut idle, 1, 0),
    );

    // Seven: the demo parameters keep one.
    let mut demo_listener = SessionOf::<1, 2, MAX_KEY_BYTES, 4>::with_params(
        Role::Listener,
        &listener_config(),
        Params::DEMO,
    )
    .expect("demo listener");
    let mut demo_connector = SessionOf::<1, 2, MAX_KEY_BYTES, 4>::with_params(
        Role::Connector,
        &connector_config(),
        Params::DEMO,
    )
    .expect("demo connector");
    let mut buffer = [0u8; MAX_BATCH_BYTES];
    let syn = demo_connector
        .connect(0, &mut buffer)
        .expect("connect")
        .batch(&buffer)
        .to_vec();
    let ack = demo_listener
        .on_batch(&through_stream(&syn), 1, &mut buffer)
        .expect("ack")
        .batch(&buffer)
        .to_vec();
    let open_syn = demo_connector
        .on_batch(&through_stream(&ack), 2, &mut buffer)
        .expect("open syn")
        .batch(&buffer)
        .to_vec();
    let open_ack = demo_listener
        .on_batch(&through_stream(&open_syn), 3, &mut buffer)
        .expect("open ack")
        .batch(&buffer)
        .to_vec();
    demo_connector
        .on_batch(&through_stream(&open_ack), 4, &mut buffer)
        .expect("open");
    demo_listener
        .send_declare_subscriber(1, KEYS[0], &mut buffer)
        .expect("the first own subscription");
    let second = demo_listener
        .send_declare_subscriber(2, KEYS[1], &mut buffer)
        .map(|_| ());
    refused(&mut seen, "demo-params-second-own-subscriber", second);
    line("ok", "demo-params-keep-one");
    print_refusals(&seen);
}

/// A count that overflows when added to the other side's is refused, and a size that wraps to the table's
/// is not taken for it. The addition is checked, so a build that wraps on overflow agrees with one that
/// panics.
#[test]
fn a_count_that_overflows_the_table_size_is_invalid() {
    for (local, per_side) in [
        (usize::MAX, 1),
        (1, usize::MAX),
        (usize::MAX, usize::MAX),
        (usize::MAX - 3, 4),
    ] {
        let result = SessionOf::<1, 0, MAX_KEY_BYTES, 4>::with_params(
            Role::Listener,
            &listener_config(),
            params(local, per_side),
        );
        assert_eq!(
            result.err(),
            Some(SessionError::InvalidConfig),
            "local {local}, per_side {per_side}"
        );
    }
}
