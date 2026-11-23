//! Host tests for the Put path of a client-role link.
//!
//! A link with the client role is driven through the handshake of two runs that `rmw_zenohd` wrote, through a scripted
//! byte stream, and then publishes four Puts on the chatter key. The captures reach the test through
//! `ZENOH_RMW_ROUTER_DATA_RUNS`, one run to a line: its name, the INIT_SYN, the INIT_ACK, the OPEN_ACK and the four
//! forwarded FRAMEs, in hex. The forwarded FRAMEs are not used here. The `[zenoh-exam] clientput` lines are what
//! `scripts/lib/zenoh_rmw_client_put_exam.py` judges; each is printed after the assertions of its scenario passed.

use super::*;
use crate::zenoh_profile0::Bounds;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const ZID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const LEASE_MS: u64 = 10_000;
const INITIAL_SN: u32 = 7;
const PAYLOAD: usize = 32;
const NOTICES: usize = 8;
const PUTS: usize = 4;
const GID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

type PutLink = LinkOf<Scripted, DEMO_FRAMED, 1, 2, MAX_KEY_BYTES, PAYLOAD, NOTICES, MAX_EVENTS>;

/// One captured run: its name and the INIT_ACK and OPEN_ACK of the router.
struct Run {
    name: String,
    ack: Vec<u8>,
    open_ack: Vec<u8>,
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "an odd number of hex digits");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("a string takes the digits");
    }
    if out.is_empty() {
        String::from("-")
    } else {
        out
    }
}

fn line(text: &str) {
    std::println!("[zenoh-exam] clientput {text}");
}

fn framed(batch: &[u8]) -> Vec<u8> {
    let mut out = (batch.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(batch);
    out
}

fn runs() -> Option<Vec<Run>> {
    let record = std::env::var("ZENOH_RMW_ROUTER_DATA_RUNS").ok()?;
    Some(
        record
            .lines()
            .map(|row| {
                let fields: Vec<&str> = row.split(' ').collect();
                assert_eq!(
                    fields.len(),
                    8,
                    "a run is a name, three handshake batches and four frames"
                );
                Run {
                    name: String::from(fields[0]),
                    ack: unhex(fields[2]),
                    open_ack: unhex(fields[3]),
                }
            })
            .collect(),
    )
}

// ------------------------------------------------------------------------------------------ the byte stream

#[derive(Default)]
struct Pipe {
    bytes: VecDeque<u8>,
}

/// One end of a scripted stream: it reads what the test feeds it and logs every byte the link writes. A budget of
/// `Some(n)` takes at most `n` more bytes, so a stalled stream leaves a batch in the link's send slot.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    budget: Rc<RefCell<Option<usize>>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let left = *self.budget.borrow();
        let take = left.map_or(buf.len(), |left| left.min(buf.len()));
        if let Some(left) = left {
            *self.budget.borrow_mut() = Some(left - take);
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
        false
    }
}

fn params() -> Params {
    let mut params = Params::DEMO;
    params.bounds.payload = PAYLOAD;
    params.samples = NOTICES / 2;
    params
}

fn config(cookie: &'static [u8]) -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: INITIAL_SN,
        cookie,
    }
}

struct Rig {
    link: PutLink,
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
    budget: Rc<RefCell<Option<usize>>>,
}

impl Rig {
    /// A connector link, with the client role when `client` is set.
    fn connector(client: bool) -> Self {
        let rx = Rc::new(RefCell::new(Pipe::default()));
        let wrote = Rc::new(RefCell::new(Vec::new()));
        let budget = Rc::new(RefCell::new(None));
        let io = Scripted {
            rx: rx.clone(),
            wrote: wrote.clone(),
            budget: budget.clone(),
        };
        let link =
            PutLink::with_params(io, Role::Connector, &config(&[]), params(), 1).expect("a link");
        let link = if client {
            link.with_client_role()
                .expect("a connector takes the client role")
        } else {
            link
        };
        Self {
            link,
            rx,
            wrote,
            budget,
        }
    }

    fn pump(&mut self) {
        let handle = self.link.handle();
        self.link
            .pump(handle, 0)
            .expect("the link takes the stream");
    }

    /// Pumps until a pump neither reads nor writes and no batch waits in the send slot.
    fn settle(&mut self) {
        for _ in 0..4000 {
            let handle = self.link.handle();
            let report = self
                .link
                .pump(handle, 0)
                .expect("the link takes the stream");
            if report.batches + report.sent_bytes == 0
                && !self.link.send_pending()
                && self.rx.borrow().bytes.is_empty()
            {
                return;
            }
        }
        panic!("the link did not settle");
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.rx.borrow_mut().bytes.extend(bytes.iter().copied());
    }

    fn written(&self) -> Vec<u8> {
        self.wrote.borrow().clone()
    }

    /// Opens the session: the INIT_SYN, the router's INIT_ACK, the OPEN_SYN and the router's OPEN_ACK, fed in `mode`.
    fn open(&mut self, run: &Run, mode: Mode) {
        let handle = self.link.handle();
        self.link.open(handle, 0).expect("the INIT_SYN is queued");
        self.settle();
        for batch in [&run.ack, &run.open_ack] {
            match mode {
                Mode::Whole | Mode::Coalesced => self.feed(&framed(batch)),
                Mode::Bytewise => {
                    for byte in framed(batch) {
                        self.feed(&[byte]);
                        self.pump();
                    }
                }
            }
            self.settle();
        }
        assert_eq!(self.link.session().state(), State::Open);
    }
}

#[derive(Clone, Copy)]
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

// ----------------------------------------------------------------------------------------------- the scenarios

fn cdr_string(text: &str) -> Vec<u8> {
    let mut out = std::vec![0x00, 0x01, 0x00, 0x00];
    out.extend_from_slice(&(text.len() as u32 + 1).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}

fn attachment(number: usize) -> [u8; 33] {
    encode::attachment(number as i64 + 1, 1_000_000_000 + number as i64, &GID)
        .expect("an attachment")
}

/// Publishes the four Puts of the exam, pumping between them so each finds the send slot free.
fn publish_puts(rig: &mut Rig) {
    let handle = rig.link.handle();
    for number in 0..PUTS {
        let payload = cdr_string(&std::format!("Hello Slime {number}"));
        rig.link
            .publish(handle, KEY, &attachment(number), &payload)
            .expect("a client-role link writes a Put with no declaration from its peer");
        rig.settle();
    }
}

fn run_session(run: &Run, mode_name: &str, mode: Mode) {
    let mut rig = Rig::connector(true);
    rig.open(run, mode);
    publish_puts(&mut rig);
    line(&std::format!(
        "sent {} {mode_name} {}",
        run.name,
        hex(&rig.written())
    ));

    let before = rig.written().len();
    let handle = rig.link.handle();
    rig.link.close(handle, 0).expect("a local close");
    rig.settle();
    let wrote = rig.written()[before..].to_vec();
    let mut reason = None;
    while let Some(notice) = rig.link.next_notice() {
        if let Notice::Closed { reason: reported } = notice {
            reason = Some(reported);
        }
    }
    let reason = reason.expect("a local close reports its reason");
    let subscription = match rig.link.session().subscriber_id() {
        Some(id) => std::format!("{id}"),
        None => String::from("none"),
    };
    line(&std::format!(
        "closed {} {mode_name} reason={reason} wrote={} subscription={subscription}",
        run.name,
        hex(&wrote)
    ));
    line(&std::format!("ok {}-{mode_name}", run.name));
}

fn class(error: Error) -> &'static str {
    match error {
        Error::Session(error) => error.class(),
        Error::Encode(_) => "encode",
        Error::SendBusy => "send-busy",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

#[test]
fn the_client_put_exam() {
    let Some(runs) = runs() else {
        return;
    };
    for run in &runs {
        line(&std::format!(
            "fed {} {} {}",
            run.name,
            hex(&run.ack),
            hex(&run.open_ack)
        ));
        for (mode_name, mode) in MODES {
            run_session(run, mode_name, mode);
        }
    }
    let run = &runs[0];
    let payload = cdr_string("Hello Slime 0");

    // A link with no client role refuses a Put on a key its peer did not declare. A router declares none, and a
    // peer's INIT_ACK is the only one a no-role connector takes, so this link is opened with a peer's handshake.
    let mut peer = Rig::connector(false);
    let handle = peer.link.handle();
    peer.link.open(handle, 0).expect("the INIT_SYN is queued");
    peer.settle();
    let ack = encode_peer_ack();
    peer.feed(&framed(&ack));
    peer.settle();
    let open_ack = encode_peer_open_ack();
    peer.feed(&framed(&open_ack));
    peer.settle();
    assert_eq!(peer.link.session().state(), State::Open);
    let error = peer
        .link
        .publish(handle, KEY, &attachment(0), &payload)
        .expect_err("a link with no role refuses an undeclared key");
    line(&std::format!(
        "refused no-role-link-puts-on-an-undeclared-key {}",
        class(error)
    ));

    // A client-role link refuses a Put before the session is open.
    let mut rig = Rig::connector(true);
    let handle = rig.link.handle();
    let error = rig
        .link
        .publish(handle, KEY, &attachment(0), &payload)
        .expect_err("a Put before the session is open");
    line(&std::format!(
        "refused client-put-before-the-session-is-open {}",
        class(error)
    ));

    // A payload over the bound and a short attachment are refused by the encoder, with the session open.
    let mut rig = Rig::connector(true);
    rig.open(run, Mode::Whole);
    let handle = rig.link.handle();
    let long = cdr_string(&"x".repeat(PAYLOAD));
    let error = rig
        .link
        .publish(handle, KEY, &attachment(0), &long)
        .expect_err("a payload over the bound");
    line(&std::format!(
        "refused client-put-over-the-payload-bound {}",
        class(error)
    ));
    let error = rig
        .link
        .publish(handle, KEY, &attachment(0)[..32], &payload)
        .expect_err("a short attachment");
    line(&std::format!(
        "refused client-put-with-a-short-attachment {}",
        class(error)
    ));

    // A Put while the send slot holds a batch is `send-busy`: a stalled stream takes no byte.
    *rig.budget.borrow_mut() = Some(0);
    rig.link
        .publish(handle, KEY, &attachment(0), &payload)
        .expect("the first Put is queued");
    rig.pump();
    assert!(
        rig.link.send_pending(),
        "the stalled stream left the Put in the slot"
    );
    let error = rig
        .link
        .publish(handle, KEY, &attachment(1), &payload)
        .expect_err("a Put while the send slot is busy");
    line(&std::format!(
        "refused client-put-while-the-send-slot-is-busy {}",
        class(error)
    ));
}

/// A peer's INIT_ACK, so a link with no client role can reach `Open` and meet the undeclared-key refusal.
fn encode_peer_ack() -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let len = encode::init_ack(&mut out, &[0xb2; 8], 512, &[0xc0; 8]).expect("an INIT_ACK");
    out[..len].to_vec()
}

fn encode_peer_open_ack() -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let len = encode::open_ack(&mut out, 30_000, 9).expect("an OPEN_ACK");
    out[..len].to_vec()
}

/// A heap link, which can write a Put in fragments. Its payload bound is large enough that one Put needs several.
type HeapLink = LinkOf<Scripted, DEMO_FRAMED, 1, 2, MAX_KEY_BYTES, 0, 4, MAX_EVENTS>;

fn heap_params() -> Params {
    Params {
        fragments: true,
        timeout_ms: 5000,
        message_limit: 4096,
        bounds: Bounds {
            payload: 1024,
            ..Bounds::DEMO
        },
        samples: 2,
        ..Params::DEMO
    }
}

/// A Put in fragments keeps the declared-key check for a client-role session too: no exam observes a client writing
/// fragments, so that path does not change. This test does not print an exam line.
#[test]
fn a_client_role_fragment_keeps_the_declared_key_check() {
    let rx = Rc::new(RefCell::new(Pipe::default()));
    let wrote = Rc::new(RefCell::new(Vec::new()));
    let io = Scripted {
        rx: rx.clone(),
        wrote: wrote.clone(),
        budget: Rc::new(RefCell::new(None)),
    };
    let mut link = HeapLink::with_params(io, Role::Connector, &config(&[]), heap_params(), 1)
        .expect("a heap link")
        .with_client_role()
        .expect("a connector takes the client role");
    let handle = link.handle();
    link.open(handle, 0).expect("the INIT_SYN is queued");
    for _ in 0..8 {
        link.pump(handle, 0).expect("the link takes the stream");
    }
    let mut ack = [0u8; MAX_BATCH_BYTES];
    let len = encode::init_ack(&mut ack, &[0x10; 8], 512, &[0xc0; 8]).expect("an INIT_ACK");
    // A client takes only a router's INIT_ACK, so the packed byte is rewritten to whatami 0.
    ack[2] &= !3;
    rx.borrow_mut().bytes.extend(framed(&ack[..len]));
    for _ in 0..8 {
        link.pump(handle, 0).expect("the link takes the stream");
    }
    let mut open_ack = [0u8; MAX_BATCH_BYTES];
    let len = encode::open_ack(&mut open_ack, 60_000, 9).expect("an OPEN_ACK");
    rx.borrow_mut().bytes.extend(framed(&open_ack[..len]));
    for _ in 0..8 {
        link.pump(handle, 0).expect("the link takes the stream");
    }
    assert_eq!(link.session().state(), State::Open);
    let payload = std::vec![0x5a; 900];
    let error = link
        .publish_part(handle, KEY, &attachment(0), &payload, 0)
        .expect_err("a fragment on a key the peer did not declare");
    assert_eq!(error, Error::Session(SessionError::UndeclaredKey));
}
