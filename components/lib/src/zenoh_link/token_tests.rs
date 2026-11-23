//! Host tests for the liveliness tokens of a client-role link.
//!
//! A link with the client role is driven through the handshake of two runs that `rmw_zenohd` wrote, through a scripted
//! byte stream, and then declares the node token and the publisher token of `slime_node`, withdraws the publisher token
//! and closes. The captures reach the test through `ZENOH_RMW_ROUTER_DATA_RUNS`, one run to a line: its name, the
//! INIT_SYN, the INIT_ACK, the OPEN_ACK and the four forwarded FRAMEs, in hex. The forwarded FRAMEs are not used here.
//! The `[zenoh-exam] clienttoken` lines are what `scripts/lib/zenoh_rmw_token_exam.py` judges; each is printed after the
//! assertions of its scenario passed. The `held` line is read from the link's own token set.

use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

/// The key of the chatter topic, used to build the publisher token's key.
const CHATTER: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const ZID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const LEASE_MS: u64 = 10_000;
const INITIAL_SN: u32 = 7;
const PAYLOAD: usize = 32;
/// The longest key the test link is declared with: a publisher token's key is 186 bytes.
const KEY_BOUND: usize = 253;
const NOTICES: usize = 8;

type TokenLink = LinkOf<Scripted, DEMO_FRAMED, 1, 2, KEY_BOUND, PAYLOAD, NOTICES, MAX_EVENTS>;

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
    std::println!("[zenoh-exam] clienttoken {text}");
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
    params.bounds.key = KEY_BOUND;
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
    link: TokenLink,
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
            TokenLink::with_params(io, Role::Connector, &config(&[]), params(), 1).expect("a link");
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

const NODE_ID: u32 = 10;
const PUBLISHER_ID: u32 = 11;

/// The tokens of `slime_node`, in the form `rmw_zenoh_cpp` names them: `@ros2_lv/<domain>/<zid>/<nid>/<id>/<kind>/...`.
/// The enclave and namespace are `/`, which the key writes as `%`. The type hash and the topic come from the chatter key.
fn zid_hex() -> String {
    ZID.iter().map(|byte| std::format!("{byte:02x}")).collect()
}

fn node_key() -> String {
    std::format!("@ros2_lv/0/{}/0/0/NN/%/%/slime_node", zid_hex())
}

fn publisher_key() -> String {
    let hash = CHATTER.rsplit('/').next().expect("a type hash");
    std::format!(
        "@ros2_lv/0/{}/0/1/MP/%/%/slime_node/%chatter/std_msgs::msg::dds_::String_/{hash}/::,:,:,:,,",
        zid_hex()
    )
}

/// The ids the link holds, as the exam prints them: `tokens=<count> ids=<comma list>`, or `tokens=0 ids=-`.
fn held(link: &TokenLink) -> String {
    let ids = link.session().tokens_held();
    if ids.is_empty() {
        return String::from("tokens=0 ids=-");
    }
    let list: Vec<String> = ids.iter().map(|id| std::format!("{id}")).collect();
    std::format!("tokens={} ids={}", ids.len(), list.join(","))
}

fn run_session(run: &Run, mode_name: &str, mode: Mode) {
    let mut rig = Rig::connector(true);
    rig.open(run, mode);
    let handle = rig.link.handle();
    rig.link
        .declare_token(handle, NODE_ID, &node_key())
        .expect("the node token is queued");
    rig.settle();
    rig.link
        .declare_token(handle, PUBLISHER_ID, &publisher_key())
        .expect("the publisher token is queued");
    rig.settle();
    rig.link
        .withdraw_token(handle, PUBLISHER_ID)
        .expect("the withdrawal is queued");
    rig.settle();
    line(&std::format!(
        "sent {} {mode_name} {}",
        run.name,
        hex(&rig.written())
    ));
    line(&std::format!(
        "held {} {mode_name} {}",
        run.name,
        held(&rig.link)
    ));

    let before = rig.written().len();
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
    let tokens = match rig.link.session().tokens_held().len() {
        0 => String::from("none"),
        count => std::format!("{count}"),
    };
    line(&std::format!(
        "closed {} {mode_name} reason={reason} wrote={} tokens={tokens}",
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
fn the_client_token_exam() {
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

    // A link with no client role declares no token: a router lists a node from the tokens its client writes.
    let mut rig = Rig::connector(false);
    let handle = rig.link.handle();
    let error = rig
        .link
        .declare_token(handle, NODE_ID, &node_key())
        .expect_err("a link with no role writes no token");
    line(&std::format!(
        "refused no-role-link-declares-a-token {}",
        class(error)
    ));

    // A token before the session is open.
    let mut rig = Rig::connector(true);
    let handle = rig.link.handle();
    let error = rig
        .link
        .declare_token(handle, NODE_ID, &node_key())
        .expect_err("a token before the session is open");
    line(&std::format!(
        "refused token-before-the-session-is-open {}",
        class(error)
    ));

    // An id already declared, a key over the bound, and the withdrawal of an id never declared, with the session open.
    let mut rig = Rig::connector(true);
    rig.open(run, Mode::Whole);
    let handle = rig.link.handle();
    rig.link
        .declare_token(handle, NODE_ID, &node_key())
        .expect("the node token is queued");
    rig.settle();
    let error = rig
        .link
        .declare_token(handle, NODE_ID, &publisher_key())
        .expect_err("an id already declared");
    line(&std::format!(
        "refused token-with-an-id-already-declared {}",
        class(error)
    ));
    assert_eq!(
        rig.link.session().tokens_held(),
        &[NODE_ID],
        "a refused declaration holds no token"
    );
    let long = "k".repeat(KEY_BOUND + 1);
    let error = rig
        .link
        .declare_token(handle, PUBLISHER_ID, &long)
        .expect_err("a key over the bound");
    line(&std::format!(
        "refused token-over-the-key-bound {}",
        class(error)
    ));
    assert_eq!(
        rig.link.session().tokens_held(),
        &[NODE_ID],
        "a refused declaration holds no token"
    );
    let error = rig
        .link
        .withdraw_token(handle, PUBLISHER_ID)
        .expect_err("an id never declared");
    line(&std::format!(
        "refused withdraw-an-id-never-declared {}",
        class(error)
    ));
    assert_eq!(
        rig.link.session().tokens_held(),
        &[NODE_ID],
        "a refused withdrawal holds the tokens"
    );

    // A token while the send slot holds a batch: a stalled stream takes no byte.
    *rig.budget.borrow_mut() = Some(0);
    rig.link
        .declare_token(handle, PUBLISHER_ID, &publisher_key())
        .expect("the publisher token is queued");
    rig.pump();
    assert!(
        rig.link.send_pending(),
        "the stalled stream left the token in the slot"
    );
    let error = rig
        .link
        .withdraw_token(handle, NODE_ID)
        .expect_err("a token while the send slot is busy");
    line(&std::format!(
        "refused token-while-the-send-slot-is-busy {}",
        class(error)
    ));
}
