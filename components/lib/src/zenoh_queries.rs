//! The queries exam: Profile 0 against the sessions two stock eclipse-zenoh 1.0.0 peers wrote while one answered a
//! query and the other asked it.
//!
//! The captured bytes are `fixtures.rs`, generated from `contracts/zenoh-stock-queries/v1` and checked against
//! `scripts/lib/zenoh_queries_exam.py` by `just zenoh_queries_check`. This module replays them into sessions of
//! ours and prints one `[zenoh-exam] queries ...` line per case; `scripts/check/check-zenoh-profile0.py --slice
//! queries` owns what those lines must be.
//!
//! Our connector plays the getter and takes the queryable peer's batches. Our listener plays the queryable and
//! takes the getter's. Each message our side writes is compared with the bytes the stock peer wrote for it.

mod fixtures;

use crate::zenoh_profile0::encode::QueryTarget;
use crate::zenoh_profile0::session::{Config, Event, Role, Session, SessionError, State};
use crate::zenoh_profile0::{
    GID_BYTES, MAX_ATTACHMENT_BYTES, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_PAYLOAD_BYTES, Message,
    Network, QueryKey, StreamFramer, decode_batch,
};
use std::string::String;
use std::vec::Vec;

const KEY: &str = "slime_demo/query";
const REPLIES: [&[u8]; 2] = [b"answer-1", b"answer-2"];
const TIMEOUT_MS: u32 = 3000;
const REQUEST: &str = "asks-04-request";
const UNDECLARE: &str = "answers-07-undeclare-queryable";

fn line(text: &str) {
    println!("[zenoh-exam] queries {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A batch a peer sent, by name.
fn captured(name: &str) -> Vec<u8> {
    fixtures::QUERYABLE_PEER
        .iter()
        .chain(fixtures::GETTER_PEER.iter())
        .chain(fixtures::REFUSE.iter())
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, bytes)| unhex(bytes))
        .unwrap_or_else(|| panic!("no captured batch named {name}"))
}

/// The offset just past a FRAME's sequence-number varint.
fn after_sn(batch: &[u8]) -> usize {
    let mut at = 1;
    while batch[at] & 0x80 != 0 {
        at += 1;
    }
    at + 1
}

/// What a FRAME carries after its header and sequence number.
fn messages(batch: &[u8]) -> &[u8] {
    &batch[after_sn(batch)..]
}

#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Handshake,
    QueryableDeclared(u32),
    QueryableUndeclared(u32),
    Query { request: u32, timeout_ms: u32 },
    Reply { request: u32, payload: Vec<u8> },
    Finished(u32),
    Closed(u8),
}

type Snapshot = (
    State,
    u32,
    u32,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u64>,
);

fn snapshot(session: &Session) -> Snapshot {
    (
        session.state(),
        session.expected_rx_sn(),
        session.next_tx_sn(),
        session.peer_queryable(),
        session.peer_request(),
        session.own_request(),
        session.lease_deadline(),
    )
}

fn owned(events: &crate::zenoh_profile0::session::Events<'_>) -> Vec<Ev> {
    events
        .iter()
        .map(|event| match *event {
            Event::HandshakeComplete => Ev::Handshake,
            Event::QueryableDeclared { id } => Ev::QueryableDeclared(id),
            Event::QueryableUndeclared { id } => Ev::QueryableUndeclared(id),
            Event::QueryReceived {
                request,
                timeout_ms,
            } => Ev::Query {
                request,
                timeout_ms,
            },
            Event::ReplyDelivered { request, payload } => Ev::Reply {
                request,
                payload: payload.to_vec(),
            },
            Event::QueryFinished { request } => Ev::Finished(request),
            Event::Closed { reason } => Ev::Closed(reason),
            other => panic!("the exam raised an event it does not name: {other:?}"),
        })
        .collect()
}

/// Feeds `batch` to `session` and returns what it sent and the events it raised.
fn feed(
    session: &mut Session,
    batch: &[u8],
    now_ms: u64,
) -> Result<(Vec<u8>, Vec<Ev>), SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(batch, now_ms, &mut out)?;
    Ok((outcome.batch(&out).to_vec(), owned(&outcome.events)))
}

fn feed_named(session: &mut Session, name: &str, now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    feed(session, &captured(name), now_ms).unwrap_or_else(|error| panic!("{name}: {error:?}"))
}

/// Replays a captured batch, which must be accepted, and reports it.
fn replay(session: &mut Session, name: &str, now_ms: u64) -> (Vec<u8>, Vec<Ev>) {
    let result = feed_named(session, name, now_ms);
    line(&format!("replay {name} ok"));
    result
}

fn connector_config() -> Config<'static> {
    Config {
        zid: &[0xa1; 8],
        lease_ms: 10_000,
        initial_sn: 9000,
        cookie: &[],
    }
}

/// The queryable peer's zenoh id, read from its INIT_ACK. Our listener announces it, so the responder extension
/// of a RESPONSE we write names the id the stock peer's names.
fn queryable_zid() -> Vec<u8> {
    let batch = captured("answers-01-init-ack");
    match decode_batch(&batch) {
        Ok(Message::InitAck { zid, .. }) => zid.to_vec(),
        other => panic!("answers-01-init-ack is not an INIT_ACK: {other:?}"),
    }
}

/// The cookie the getter echoed in its OPEN_SYN, which our listener must hold to take that OPEN_SYN.
fn getter_cookie() -> Vec<u8> {
    let batch = captured("asks-02-open-syn");
    match decode_batch(&batch) {
        Ok(Message::OpenSyn { cookie, .. }) => cookie.to_vec(),
        other => panic!("asks-02-open-syn is not an OPEN_SYN: {other:?}"),
    }
}

/// A listener that has taken the getter's first three batches, and the time after them.
fn open_listener() -> (Session, u64) {
    let (zid, cookie) = (queryable_zid(), getter_cookie());
    let config = Config {
        zid: &zid,
        lease_ms: 10_000,
        initial_sn: 200,
        cookie: &cookie,
    };
    let mut ours = Session::new(Role::Listener, &config).expect("listener");
    for (at, name) in [
        "asks-01-init-syn",
        "asks-02-open-syn",
        "asks-03-oam-declare-final",
    ]
    .into_iter()
    .enumerate()
    {
        feed_named(&mut ours, name, 1 + at as u64);
    }
    assert!(ours.is_open());
    (ours, 4)
}

/// An open listener that has declared its queryable, as the stock queryable did before the request.
fn declared_listener() -> (Session, u64) {
    let (mut ours, now) = open_listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.send_declare_queryable(1, 1, KEY, &mut out)
        .expect("declare");
    (ours, now)
}

/// A connector that has taken the queryable peer's first three batches and so holds its queryable.
fn connector_with_declaration() -> (Session, u64) {
    let mut ours = Session::new(Role::Connector, &connector_config()).expect("connector");
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.connect(0, &mut out).expect("connect");
    for (at, name) in [
        "answers-01-init-ack",
        "answers-02-open-ack",
        "answers-03-oam-declare-queryable-final",
    ]
    .into_iter()
    .enumerate()
    {
        feed_named(&mut ours, name, 1 + at as u64);
    }
    assert!(ours.is_open());
    assert_eq!(ours.peer_queryable(), Some(1));
    (ours, 4)
}

/// A connector with its request out, as it is when the stock queryable answers.
fn connector_with_request() -> (Session, u64) {
    let (mut ours, now) = connector_with_declaration();
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.send_request(1, QueryTarget::ReceiverAlias(1), TIMEOUT_MS, &mut out)
        .expect("request");
    (ours, now)
}

/// A connector whose request the stock queryable has answered and ended.
fn connector_after_final() -> (Session, u64) {
    let (mut ours, now) = connector_with_request();
    for (at, name) in [
        "answers-04-response-1",
        "answers-05-response-2",
        "answers-06-response-final",
    ]
    .into_iter()
    .enumerate()
    {
        feed_named(&mut ours, name, now + at as u64);
    }
    assert_eq!(ours.own_request(), None);
    (ours, now + 3)
}

/// Our query, answered by the stock queryable: our request is the bytes the stock getter wrote, both replies
/// are delivered, the replies end, and the queryable is withdrawn by id.
fn stock_queryable_answers_our_query() {
    let mut ours = Session::new(Role::Connector, &connector_config()).expect("connector");
    let mut out = [0u8; MAX_BATCH_BYTES];
    ours.connect(0, &mut out).expect("connect");
    let mut now = 0;
    let mut step = |ours: &mut Session, name: &str| {
        now += 1;
        replay(ours, name, now)
    };

    let (_open_syn, events) = step(&mut ours, "answers-01-init-ack");
    assert!(events.is_empty());
    let (_, events) = step(&mut ours, "answers-02-open-ack");
    assert_eq!(events, [Ev::Handshake]);
    let (_, events) = step(&mut ours, "answers-03-oam-declare-queryable-final");
    assert_eq!(events, [Ev::QueryableDeclared(1)]);
    assert_eq!(ours.peer_queryable(), Some(1));

    let sent = ours
        .send_request(1, QueryTarget::ReceiverAlias(1), TIMEOUT_MS, &mut out)
        .expect("request");
    let request = sent.batch(&out).to_vec();
    assert_eq!(
        messages(&request),
        messages(&captured(REQUEST)),
        "our request is not the bytes the stock getter wrote"
    );
    assert_eq!(ours.own_request(), Some(1));

    for (number, (name, payload)) in [
        ("answers-04-response-1", REPLIES[0]),
        ("answers-05-response-2", REPLIES[1]),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, events) = step(&mut ours, name);
        assert_eq!(
            events,
            [Ev::Reply {
                request: 1,
                payload: payload.to_vec()
            }]
        );
        let [Ev::Reply { payload: seen, .. }] = events.as_slice() else {
            unreachable!("the assertion above holds one reply");
        };
        line(&format!("delivered {} {}", number + 1, hex(seen)));
    }
    let (_, events) = step(&mut ours, "answers-06-response-final");
    assert_eq!(events, [Ev::Finished(1)]);
    assert_eq!(ours.own_request(), None);
    let (_, events) = step(&mut ours, UNDECLARE);
    assert_eq!(events, [Ev::QueryableUndeclared(1)]);
    assert_eq!(ours.peer_queryable(), None);
    let (_, events) = step(&mut ours, "answers-08-keep-alive");
    assert!(events.is_empty());
    assert!(ours.is_open());
    line("ok stock-queryable-answers-our-query");
}

/// A stock peer's query, reaching our queryable: our declaration is the messages the stock queryable wrote, the
/// request is taken, and our replies and final response are the bytes the stock queryable wrote.
fn stock_peer_queries_our_queryable() {
    let (zid, cookie) = (queryable_zid(), getter_cookie());
    let config = Config {
        zid: &zid,
        lease_ms: 10_000,
        initial_sn: 200,
        cookie: &cookie,
    };
    let mut ours = Session::new(Role::Listener, &config).expect("listener");
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut now = 0;
    let mut step = |ours: &mut Session, name: &str| {
        now += 1;
        replay(ours, name, now)
    };

    let (init_ack, events) = step(&mut ours, "asks-01-init-syn");
    assert!(events.is_empty());
    assert!(matches!(
        decode_batch(&init_ack),
        Ok(Message::InitAck { .. })
    ));
    let (_, events) = step(&mut ours, "asks-02-open-syn");
    assert_eq!(events, [Ev::Handshake]);
    let (_, events) = step(&mut ours, "asks-03-oam-declare-final");
    assert!(events.is_empty());

    let sent = ours
        .send_declare_queryable(1, 1, KEY, &mut out)
        .expect("declare");
    let declaration = sent.batch(&out).to_vec();
    let stock = captured("answers-03-oam-declare-queryable-final");
    let ours_declared = messages(&declaration);
    assert!(
        stock
            .windows(ours_declared.len())
            .any(|window| window == ours_declared),
        "our alias and queryable declaration are not the bytes the stock queryable wrote"
    );

    let (_, events) = step(&mut ours, REQUEST);
    assert_eq!(
        events,
        [Ev::Query {
            request: 1,
            timeout_ms: TIMEOUT_MS
        }]
    );
    assert_eq!(ours.peer_request(), Some(1));

    for (payload, name) in REPLIES
        .into_iter()
        .zip(["answers-04-response-1", "answers-05-response-2"])
    {
        let sent = ours
            .send_response(KEY, &zid, payload, &mut out)
            .expect("response");
        assert_eq!(
            messages(sent.batch(&out)),
            messages(&captured(name)),
            "our response is not the bytes the stock queryable wrote for {name}"
        );
    }
    assert_eq!(ours.peer_request(), Some(1));
    let sent = ours.send_response_final(&mut out).expect("final");
    assert_eq!(
        messages(sent.batch(&out)),
        messages(&captured("answers-06-response-final")),
        "our final response is not the bytes the stock queryable wrote"
    );
    assert_eq!(ours.peer_request(), None);
    assert!(matches!(
        ours.send_response_final(&mut out),
        Err(SessionError::UnexpectedMessage)
    ));

    let (_, events) = step(&mut ours, "asks-05-keep-alive");
    assert!(events.is_empty());
    let (_, events) = step(&mut ours, "asks-06-close");
    assert_eq!(events, [Ev::Closed(0)]);
    assert_eq!(ours.state(), State::Closed);
    line("ok stock-peer-queries-our-queryable");
}

/// Our queryable, withdrawn by id: the bytes are the ones the stock queryable wrote, a second withdrawal is
/// refused, and a request after it finds no queryable.
fn queryable_undeclared_by_id() {
    let (mut ours, now) = declared_listener();
    let mut out = [0u8; MAX_BATCH_BYTES];
    let sent = ours.send_undeclare_queryable(&mut out).expect("undeclare");
    assert_eq!(
        messages(sent.batch(&out)),
        messages(&captured(UNDECLARE)),
        "our withdrawal is not the bytes the stock queryable wrote"
    );
    assert!(matches!(
        ours.send_undeclare_queryable(&mut out),
        Err(SessionError::UnknownQueryable)
    ));
    let before = snapshot(&ours);
    let error =
        feed(&mut ours, &captured(REQUEST), now).expect_err("a request after the withdrawal");
    assert!(matches!(error, SessionError::UndeclaredKey));
    assert_eq!(snapshot(&ours), before);
    line("ok queryable-undeclared-by-id");
}

/// Each variant, through a session in the state its refusal needs, which must come out unchanged.
fn refusals() {
    for (name, bytes) in fixtures::REFUSE {
        let (mut ours, now) = match name {
            "refuse-request-without-queryable" => open_listener(),
            "refuse-response-nobody-asked-for" => connector_with_declaration(),
            "refuse-response-final-repeated" => connector_after_final(),
            other if other.starts_with("refuse-request-") => declared_listener(),
            _ => connector_with_request(),
        };
        let before = snapshot(&ours);
        let error = feed(&mut ours, &unhex(bytes), now + 10).expect_err(name);
        assert_eq!(snapshot(&ours), before, "{name} changed the session");
        line(&format!("refused {name} {}", error.class()));
    }
}

fn bounded(frame: &crate::zenoh_profile0::Frame<'_>) {
    let within = |key: QueryKey<'_>| {
        if let QueryKey::Full(key) = key {
            assert!(key.len() <= MAX_KEY_BYTES);
        }
    };
    for message in frame.messages() {
        match message {
            Network::DeclareSubscriber { key, .. }
            | Network::UndeclareSubscriber { key, .. }
            | Network::DeclareKeyExpr { key, .. } => assert!(key.len() <= MAX_KEY_BYTES),
            Network::PushPut {
                key,
                attachment,
                payload,
                ..
            } => {
                assert!(key.len() <= MAX_KEY_BYTES);
                assert_eq!(attachment.raw.len(), MAX_ATTACHMENT_BYTES);
                assert_eq!(attachment.gid.len(), GID_BYTES);
                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
            }
            Network::PushPutAlias {
                attachment,
                payload,
                ..
            } => {
                assert_eq!(attachment.raw.len(), MAX_ATTACHMENT_BYTES);
                assert_eq!(attachment.gid.len(), GID_BYTES);
                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
            }
            Network::DeclareQueryable { key, .. } | Network::Request { key, .. } => within(key),
            Network::Response { key, payload, .. } => {
                within(key);
                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
            }
            Network::DeclareSubscriberAlias { .. }
            | Network::UndeclareSubscriberById { .. }
            | Network::UndeclareQueryable { .. }
            | Network::ResponseFinal { .. }
            | Network::Oam
            | Network::DeclareFinal => {}
        }
    }
}

/// No proper prefix is accepted unless it is a shorter frame, a flipped bit never panics or exceeds a bound, and
/// every two-chunk split of the framed batch reassembles to it.
fn properties(name: &str, batch: &[u8]) {
    let whole = match decode_batch(batch) {
        Ok(Message::Frame(frame)) => Some(frame.messages().count()),
        Ok(_) => None,
        Err(refusal) => panic!("{name} is not accepted: {refusal:?}"),
    };
    for length in 0..batch.len() {
        match decode_batch(&batch[..length]) {
            Err(_) => {}
            Ok(Message::Frame(frame)) => {
                let total = whole.unwrap_or_else(|| {
                    panic!("{name}: a non-frame decoded a {length}-byte prefix")
                });
                assert!(
                    frame.messages().count() < total,
                    "{name}: a {length}-byte prefix decoded as much as the whole"
                );
            }
            Ok(_) => panic!("{name}: a {length}-byte prefix decoded"),
        }
    }
    for position in 0..batch.len() {
        for flip in [0x01u8, 0x80] {
            let mut mutated = batch.to_vec();
            mutated[position] ^= flip;
            if let Ok(Message::Frame(frame)) = decode_batch(&mutated) {
                bounded(&frame);
            }
        }
    }
    let mut framed = (batch.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(batch);
    for cut in 1..framed.len() {
        let mut framer = StreamFramer::new();
        assert_eq!(framer.push(&framed[..cut]), cut);
        if let Ok(Some(_)) = framer.peek_batch() {
            panic!("{name}: complete before its last byte at {cut}");
        }
        assert_eq!(framer.push(&framed[cut..]), framed.len() - cut);
        assert_eq!(
            framer.peek_batch().expect("prefix"),
            Some(batch),
            "{name} split at {cut}"
        );
        framer.consume_batch();
        assert_eq!(framer.pending(), 0);
    }
    line(&format!("property {name} ok"));
}

#[test]
fn the_constants_are_the_handed_off_record() {
    assert_eq!(fixtures::FORMAT_VERSION, 1);
    let Some(path) = std::env::var_os("ZENOH_QUERIES_FIXTURES") else {
        return;
    };
    let record = std::fs::read_to_string(&path).expect("the hand-off record is readable");
    let mut wanted = String::new();
    wanted.push_str("{\n");
    wanted.push_str(&format!(
        "  formatVersion = {};\n",
        fixtures::FORMAT_VERSION
    ));
    for (group, rows) in [
        ("queryablePeer", &fixtures::QUERYABLE_PEER[..]),
        ("getterPeer", &fixtures::GETTER_PEER[..]),
        ("refuse", &fixtures::REFUSE[..]),
    ] {
        wanted.push_str(&format!("  {group} = [\n"));
        for (name, bytes) in rows {
            wanted.push_str(&format!(
                "    {{ name = \"{name}\"; hex = \"{bytes}\"; }};\n"
            ));
        }
        wanted.push_str("  ];\n");
    }
    wanted.push_str("}\n");
    assert_eq!(
        record, wanted,
        "fixtures.rs differs from the record the exam handed over; run `just zenoh_queries_gen`"
    );
}

/// Every section, in the order the exam lists them.
#[test]
fn the_stock_peer_queries_exam() {
    stock_queryable_answers_our_query();
    stock_peer_queries_our_queryable();
    queryable_undeclared_by_id();
    for (name, bytes) in fixtures::QUERYABLE_PEER
        .iter()
        .chain(fixtures::GETTER_PEER.iter())
    {
        properties(name, &unhex(bytes));
    }
    refusals();
}
