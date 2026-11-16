// The rmw link exam: the three sessions an rmw_zenoh peer sent, written to a graph link through a scripted
// byte stream.
//
// Included into `zenoh_rmw_link` so the test is named `zenoh_rmw_link::the_graph_link_exam`, as
// `scripts/check/check-zenoh-profile0.py --slice rmw-link` requires. The captured bytes are the session
// exam's fixtures, `contracts/zenoh-rmw-session/v1`. Each printed line is one the checker builds again from
// the captured bytes, `zenoh_rmw_graph` and `zenoh_wire`, so nothing printed here is trusted for its value.

use crate::zenoh_rmw::fixtures as captured;
use crate::zenoh_rmw_graph::{Entity, Qos};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::format;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const LINK_FRAMED: usize = 512;
const SLOTS: usize = 32;
const KEY: usize = 253;
const ENTITIES: usize = 16;
const SMALL_GRAPH: usize = 2;
const DOMAIN: u64 = 0;
const COOKIE: &[u8] = b"slime-rmw-capture-cookie-01";
const ZID: [u8; 16] = [
    0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
];
const LEASE_MS: u64 = 30_000;
const PEER_LEASE_MS: u64 = 60_000;
const KEEP_ALIVE_AT: u64 = LEASE_MS / 4;

type Wide = GraphLinkOf<Scripted, LINK_FRAMED, SLOTS, SLOTS, KEY, ENTITIES>;
type Small = GraphLinkOf<Scripted, LINK_FRAMED, SLOTS, SLOTS, KEY, SMALL_GRAPH>;

fn link_line(text: &str) {
    std::println!("[zenoh-exam] link {text}");
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("-");
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A batch with its two-byte stream length in front.
fn framed(batch: &[u8]) -> Vec<u8> {
    let mut out = (batch.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(batch);
    out
}

// ------------------------------------------------------------------------------------ the byte stream

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
    closed: bool,
}

/// One end of a scripted stream: it reads what the exam feeds it and logs every byte the link writes.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    tx_closed: Rc<Cell<bool>>,
    /// Bytes `send` still accepts in this pump; `None` accepts every byte.
    budget: Rc<Cell<Option<usize>>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        if self.tx_closed.get() {
            return Err(LinkError::Closed);
        }
        let take = self.budget.get().map_or(buf.len(), |left| left.min(buf.len()));
        if let Some(left) = self.budget.get() {
            self.budget.set(Some(left - take));
        }
        self.wrote.borrow_mut().extend_from_slice(&buf[..take]);
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
        let pipe = self.rx.borrow();
        pipe.closed && pipe.bytes.is_empty()
    }
}

/// A link, the stream beneath it, and the knobs the exam turns.
struct Rig<L> {
    link: L,
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    tx_closed: Rc<Cell<bool>>,
    budget: Rc<Cell<Option<usize>>>,
    per_pump: Option<usize>,
}

fn config() -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: 7,
        cookie: COOKIE,
    }
}

/// A scripted stream and the handles the exam keeps to it.
struct Parts {
    io: Scripted,
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    tx_closed: Rc<Cell<bool>>,
    budget: Rc<Cell<Option<usize>>>,
}

fn parts() -> Parts {
    let rx = Rc::new(RefCell::new(Pipe::default()));
    let wrote = Rc::new(RefCell::new(Vec::new()));
    let tx_closed = Rc::new(Cell::new(false));
    let budget = Rc::new(Cell::new(None));
    let io = Scripted {
        rx: rx.clone(),
        wrote: wrote.clone(),
        tx_closed: tx_closed.clone(),
        budget: budget.clone(),
    };
    Parts {
        io,
        rx,
        wrote,
        tx_closed,
        budget,
    }
}

macro_rules! rig {
    ($ty:ty, $role:expr, $generation:expr) => {{
        let Parts {
            io,
            rx,
            wrote,
            tx_closed,
            budget,
        } = parts();
        let link = <$ty>::new(io, $role, &config(), Params::GRAPH, DOMAIN, $generation)
            .expect("a graph link");
        Rig {
            link,
            rx,
            wrote,
            tx_closed,
            budget,
            per_pump: None,
        }
    }};
}

impl<L> Rig<L> {
    fn written(&self) -> Vec<u8> {
        self.wrote.borrow().clone()
    }
}

impl Rig<Wide> {
    fn handle(&self) -> GraphHandle {
        self.link.handle()
    }
}

macro_rules! rig_methods {
    ($ty:ty) => {
        impl Rig<$ty> {
            fn feed(&self, bytes: &[u8]) {
                self.rx.borrow_mut().bytes.extend(bytes.iter().copied());
            }

            /// One pump at `now`, with the bytes the stream takes limited to the exam's budget.
            fn pump(&mut self, now: u64) -> Result<PumpReport, GraphLinkError> {
                self.budget.set(self.per_pump);
                let handle = self.link.handle();
                self.link.pump(handle, now)
            }

            /// Pumps until a pump neither reads, sends nor has a batch waiting.
            fn settle(&mut self, now: u64) -> Result<(), GraphLinkError> {
                for _ in 0..4000 {
                    let report = self.pump(now)?;
                    let quiet = report.batches + report.sent_bytes == 0
                        && !self.link.send_pending()
                        && self.rx.borrow().bytes.is_empty();
                    if quiet {
                        return Ok(());
                    }
                }
                panic!("the link did not settle");
            }
        }
    };
}

rig_methods!(Wide);
rig_methods!(Small);

// ------------------------------------------------------------------------------------------- printing

fn demangled(text: &str) -> String {
    text.replace('%', "/")
}

fn duration(pair: (u64, u64)) -> String {
    format!("{}.{}", pair.0, pair.1)
}

fn qos_text(qos: &Qos) -> String {
    format!(
        "rel={},dur={},his={},dep={},dl={},ls={},lv={},le={}",
        qos.reliability,
        qos.durability,
        qos.history,
        qos.depth,
        duration(qos.deadline),
        duration(qos.lifespan),
        qos.liveliness,
        duration(qos.lease)
    )
}

fn entity_line(entity: &Entity) -> String {
    let none = String::from("-");
    let (topic, type_name, type_hash, qos) = match entity.topic() {
        Some(topic) => (
            demangled(topic),
            demangled(entity.type_name().expect("a topic has a type")),
            demangled(entity.type_hash().expect("a topic has a hash")),
            qos_text(entity.qos().expect("a topic has a QoS")),
        ),
        None => (none.clone(), none.clone(), none.clone(), none),
    };
    format!(
        "{} {} {} {} {} {} {} {} {} {} {}",
        entity.kind().name(),
        entity.zid(),
        entity.nid(),
        entity.id(),
        demangled(entity.enclave()),
        demangled(entity.namespace()),
        demangled(entity.node()),
        topic,
        type_name,
        type_hash,
        qos
    )
}

// ------------------------------------------------------------------------------------------ the groups

const GROUPS: [(&str, &[(&str, &str)]); 3] = [
    ("talker", &captured::TALKER),
    ("listener", &captured::LISTENER),
    ("lists", &captured::LISTS),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Whole,
    Bytewise,
    Coalesced,
}

const MODES: [(&str, Mode); 3] = [
    ("whole", Mode::Whole),
    ("bytewise", Mode::Bytewise),
    ("coalesced", Mode::Coalesced),
];

/// A group's batches before its CLOSE, and the CLOSE.
fn session_and_close(rows: &[(&str, &str)]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut batches: Vec<Vec<u8>> = rows.iter().map(|(_, hexed)| unhex(hexed)).collect();
    let close = batches.pop().expect("a captured session has batches");
    assert_eq!(close.first().map(|header| header & 0x1f), Some(3), "a session ends in a CLOSE");
    (batches, close)
}

/// Writes every batch of a session before its CLOSE to the link in one of three ways: a batch at a time, a
/// byte at a time, or everything at once.
fn write_session<R>(rig: &mut Rig<R>, batches: &[Vec<u8>], mode: Mode)
where
    Rig<R>: Pump,
{
    match mode {
        Mode::Whole => {
            for batch in batches {
                rig.feed_bytes(&framed(batch));
                rig.settle_at(0).expect("the link took the batch");
            }
        }
        Mode::Bytewise => {
            for batch in batches {
                for byte in framed(batch) {
                    rig.feed_bytes(&[byte]);
                    rig.pump_at(0).expect("the link took the byte");
                }
                rig.settle_at(0).expect("the link took the batch");
            }
        }
        Mode::Coalesced => {
            let all: Vec<u8> = batches.iter().flat_map(|batch| framed(batch)).collect();
            rig.feed_bytes(&all);
            rig.settle_at(0).expect("the link took the session");
        }
    }
}

trait Pump {
    fn feed_bytes(&self, bytes: &[u8]);
    fn pump_at(&mut self, now: u64) -> Result<(), GraphLinkError>;
    fn settle_at(&mut self, now: u64) -> Result<(), GraphLinkError>;
}

macro_rules! pump_impl {
    ($ty:ty) => {
        impl Pump for Rig<$ty> {
            fn feed_bytes(&self, bytes: &[u8]) {
                self.feed(bytes);
            }
            fn pump_at(&mut self, now: u64) -> Result<(), GraphLinkError> {
                self.pump(now).map(|_| ())
            }
            fn settle_at(&mut self, now: u64) -> Result<(), GraphLinkError> {
                self.settle(now)
            }
        }
    };
}

pump_impl!(Wide);
pump_impl!(Small);

fn replay_groups() {
    for (group, rows) in GROUPS {
        let (batches, close) = session_and_close(rows);
        for (mode_name, mode) in MODES {
            let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
            write_session(&mut rig, &batches, mode);
            assert!(rig.link.is_open(), "{group} {mode_name}: the link is open before the peer's CLOSE");
            let ignored = rig.link.graph().ignored();
            let mut lines: Vec<String> = Vec::new();
            {
                let mut live: Vec<&Entity> = rig.link.graph().iter().collect();
                live.sort_by(|a, b| (a.zid(), a.nid(), a.id()).cmp(&(b.zid(), b.nid(), b.id())));
                for entity in live {
                    lines.push(format!("entity {group} {mode_name} {}", entity_line(entity)));
                }
            }
            rig.feed(&framed(&close));
            rig.settle(0).expect("the link took the peer's CLOSE");
            assert!(rig.link.is_closed(), "{group} {mode_name}: the peer's CLOSE ends the link");
            let reason = rig.link.close_reason().expect("a closed link has a reason");
            let after = rig.link.graph().len();
            link_line(&format!("sent {group} {mode_name} {}", hex(&rig.written())));
            for line in &lines {
                link_line(line);
            }
            link_line(&format!("ignored {group} {mode_name} {ignored}"));
            link_line(&format!("closed {group} {mode_name} reason={reason} entities={after}"));
            link_line(&format!("ok {group}-{mode_name}"));
        }
    }
}

// --------------------------------------------------------------------------------------- the scenarios

/// A listener that has taken the talker's INIT_SYN and OPEN_SYN, with nothing yet written beyond its handshake.
fn talker_handshake<R>(rig: &mut Rig<R>)
where
    Rig<R>: Pump,
{
    let (batches, _close) = session_and_close(captured::TALKER.as_ref());
    for batch in &batches[..2] {
        rig.feed_bytes(&framed(batch));
        rig.settle_at(0).expect("the handshake");
    }
}

/// A listener that has taken the whole talker session except its CLOSE, so its graph holds 11 entities.
fn talker_session<R>(rig: &mut Rig<R>)
where
    Rig<R>: Pump,
{
    let (batches, _close) = session_and_close(captured::TALKER.as_ref());
    write_session(rig, &batches, Mode::Whole);
}

fn partial_writes() {
    let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    rig.per_pump = Some(3);
    talker_handshake(&mut rig);
    link_line(&format!("sent partial-writes {}", hex(&rig.written())));
    link_line("ok partial-writes-complete-the-handshake");
}

fn keep_alive() {
    let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    talker_handshake(&mut rig);
    for at in [KEEP_ALIVE_AT - 1, KEEP_ALIVE_AT, KEEP_ALIVE_AT + 1] {
        let before = rig.written().len();
        rig.pump(at).expect("a pump");
        let wrote = rig.written()[before..].to_vec();
        link_line(&format!("probe keep-alive t={at} wrote={}", hex(&wrote)));
    }
    link_line(&format!("sent keep-alive {}", hex(&rig.written())));
    link_line("ok keep-alive-after-a-quarter-lease");
}

fn lease_expiry() {
    let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    talker_session(&mut rig);
    assert_eq!(rig.link.graph().len(), 11, "the graph holds the talker's entities before the lease runs out");
    let mut at = KEEP_ALIVE_AT;
    while at <= PEER_LEASE_MS {
        let before = rig.written().len();
        rig.pump(at).expect("a pump inside the peer's lease");
        let wrote = rig.written()[before..].to_vec();
        link_line(&format!("probe lease-expiry t={at} wrote={}", hex(&wrote)));
        assert!(!rig.link.is_closed(), "the link is open at {at} ms");
        at += KEEP_ALIVE_AT;
    }
    let before = rig.written().len();
    rig.pump(PEER_LEASE_MS + 1).expect("the pump that expires the lease");
    let wrote = rig.written()[before..].to_vec();
    link_line(&format!("probe lease-expiry t={} wrote={}", PEER_LEASE_MS + 1, hex(&wrote)));
    assert!(rig.link.is_closed(), "the link ends once the peer's lease has run out");
    // The wire's CLOSE reason for an expired lease, `closeExpired` in `contracts/zenoh-profile/v1`.
    assert_eq!(rig.link.close_reason(), Some(5));
    link_line(&format!("sent lease-expiry {}", hex(&rig.written())));
    link_line(&format!("entities lease-expiry {}", rig.link.graph().len()));
    link_line("ok lease-expiry-closes-the-link");
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The sequence number of a captured FRAME.
fn frame_sn(batch: &[u8]) -> u32 {
    let mut at = 1;
    let mut value = 0u32;
    let mut shift = 0;
    loop {
        let byte = batch[at];
        at += 1;
        value |= u32::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return value;
        }
    }
}

/// One frame of three tokens: a node `a`, a token of the unknown kind `XX`, and a node `c`, with the
/// sequence number the talker's first frame carries. Each token is a key alias and a token declaration
/// behind the network QoS extension.
fn three_token_frame() -> Vec<u8> {
    let talker = captured::TALKER.as_ref();
    let sn = frame_sn(&unhex(talker[2].1));
    let zid = "77bf039722c084d5ddae7b5ba3647a11";
    let mut frame = vec![0x25u8];
    frame.extend(leb(sn));
    for (number, (kind, node)) in [("NN", "a"), ("XX", "b"), ("NN", "c")].into_iter().enumerate() {
        let alias = 90 + number as u32;
        let ident = 91 + 2 * number as u32;
        let key = format!("@ros2_lv/0/{zid}/0/{}/{kind}/%/%/{node}", 60 + number);
        frame.extend_from_slice(&[0x9e, 0x21, 0x08, 0x20]);
        frame.extend(leb(alias));
        frame.extend(leb(0));
        frame.extend(leb(key.len() as u32));
        frame.extend_from_slice(key.as_bytes());
        // 0x46: the token declaration with the sender-mapping flag, as every captured token carries it.
        frame.extend_from_slice(&[0x9e, 0x21, 0x08, 0x46]);
        frame.extend(leb(ident));
        frame.extend(leb(alias));
    }
    frame
}

fn counted() {
    let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    talker_handshake(&mut rig);
    rig.feed(&framed(&three_token_frame()));
    rig.settle(0).expect("the frame with a token of an unknown entity");
    link_line(&format!(
        "counted token-of-an-unknown-entity {} open={} entities={}",
        rig.link.refused_tokens(),
        rig.link.is_open(),
        rig.link.graph().len()
    ));

    let mut small: Rig<Small> = rig!(Small, Role::Listener, 1);
    talker_session(&mut small);
    link_line(&format!(
        "counted graph-over-capacity {} open={} entities={}",
        small.link.refused_tokens(),
        small.link.is_open(),
        small.link.graph().len()
    ));
}

/// Finishes a refusal: the link ended, so the exam pumps once more to write the CLOSE it queued.
fn after_refusal(rig: &mut Rig<Wide>, name: &str, error: GraphLinkError) {
    assert!(rig.link.is_closed(), "{name}: the link ends");
    rig.settle(0).expect("the link flushes its CLOSE");
    link_line(&format!("refused {name} {} {}", error.class(), hex(&rig.written())));
}

fn refusals() {
    // send-stall: a connector whose stream never takes a byte stalls past the retry limit.
    let mut stalled: Rig<Wide> = rig!(Wide, Role::Connector, 1);
    stalled.per_pump = Some(0);
    let handle = stalled.handle();
    stalled.link.open(handle, 0).expect("open");
    let mut error = None;
    for _ in 0..8 {
        if let Err(found) = stalled.pump(0) {
            error = Some(found);
            break;
        }
    }
    let error = error.expect("the stalled link gives up");
    link_line(&format!("refused send-stall {} {}", error.class(), hex(&stalled.written())));

    // oversized-length-prefix and zero-length-prefix: a stream fault after the session is open.
    for (name, prefix) in [("oversized-length-prefix", [0x01u8, 0x10]), ("zero-length-prefix", [0x00u8, 0x00])] {
        let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
        talker_session(&mut rig);
        assert_eq!(rig.link.graph().len(), 11, "{name}: the graph holds the talker's entities");
        rig.feed(&prefix);
        let error = rig.pump(0).expect_err("a stream fault");
        after_refusal(&mut rig, name, error);
        link_line(&format!("entities {name} {}", rig.link.graph().len()));
    }

    // stale-handle: a handle of an earlier generation drives nothing.
    let mut current: Rig<Wide> = rig!(Wide, Role::Listener, 2);
    talker_handshake(&mut current);
    let earlier: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    let stale = earlier.handle();
    let error = current.link.pump(stale, 0).expect_err("a stale handle");
    link_line(&format!("refused stale-handle {} {}", error.class(), hex(&current.written())));

    // send-after-close: a call on a link that already ended.
    let mut closed: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    talker_handshake(&mut closed);
    let handle = closed.handle();
    closed.link.close(handle, 0).expect("close");
    closed.settle(0).expect("the CLOSE is written");
    let error = closed.link.close(handle, 0).expect_err("a call after close");
    link_line(&format!("refused send-after-close {} {}", error.class(), hex(&closed.written())));

    // end-of-stream-before-the-handshake: the peer closed the whole connection and sent nothing.
    let mut ended: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    ended.rx.borrow_mut().closed = true;
    ended.tx_closed.set(true);
    let error = ended.pump(0).expect_err("the stream ended");
    // The CLOSE the link queued cannot be written to a stream that is closed, so this pump only flushes.
    let _ = ended.pump(0);
    link_line(&format!(
        "refused end-of-stream-before-the-handshake {} {}",
        error.class(),
        hex(&ended.written())
    ));
}

fn local_close() {
    let mut rig: Rig<Wide> = rig!(Wide, Role::Listener, 1);
    talker_session(&mut rig);
    assert_eq!(rig.link.graph().len(), 11, "the graph holds the talker's entities before the local close");
    let handle = rig.handle();
    rig.link.close(handle, 0).expect("close");
    rig.settle(0).expect("the CLOSE is written");
    assert_eq!(rig.link.close_reason(), Some(0));
    link_line(&format!("close local {}", hex(&rig.written())));
    link_line(&format!("entities local-close {}", rig.link.graph().len()));
}

/// Every section, in the order the exam lists them.
#[test]
fn the_graph_link_exam() {
    replay_groups();
    partial_writes();
    keep_alive();
    lease_expiry();
    counted();
    refusals();
    local_close();
}
