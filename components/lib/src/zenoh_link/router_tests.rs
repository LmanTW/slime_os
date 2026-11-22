//! Host tests for a client-role link that subscribes through a router.
//!
//! A link with the client role is driven against two runs that `rmw_zenohd` wrote, through a scripted byte stream.
//! The captures reach the test through `ZENOH_RMW_ROUTER_DATA_RUNS`, one run to a line: its name, the INIT_SYN, the
//! INIT_ACK, the OPEN_ACK and the four forwarded FRAMEs, in hex. The `[zenoh-exam] routerlink` lines are what
//! `scripts/lib/zenoh_rmw_router_link_exam.py` judges; each is printed after the assertions of its scenario passed.

use super::*;
use crate::zenoh_profile0::session::Session;
use crate::zenoh_profile0::{Bounds, decode_batch_client, decode_batch_with};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

const KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const ZID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const LEASE_MS: u64 = 10_000;
const INITIAL_SN: u32 = 7;
const SUBSCRIPTION: u32 = 1;
const PAYLOAD: usize = 32;
const NOTICES: usize = 8;

type RouterLink = LinkOf<Scripted, DEMO_FRAMED, 1, 2, MAX_KEY_BYTES, PAYLOAD, NOTICES, MAX_EVENTS>;

/// One captured run: its name, the INIT_SYN the client wrote, the INIT_ACK and OPEN_ACK of the router, and the FRAMEs
/// the router forwarded.
struct Run {
    name: String,
    ack: Vec<u8>,
    open_ack: Vec<u8>,
    forwarded: Vec<Vec<u8>>,
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
    std::println!("[zenoh-exam] routerlink {text}");
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
                    forwarded: fields[4..].iter().map(|batch| unhex(batch)).collect(),
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

/// One end of a scripted stream: it reads what the test feeds it and logs every byte the link writes.
struct Scripted {
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
}

impl ByteLink for Scripted {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        self.wrote.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
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
    link: RouterLink,
    rx: Rc<RefCell<Pipe>>,
    wrote: Rc<RefCell<Vec<u8>>>,
}

impl Rig {
    fn new(role: Role, cookie: &'static [u8]) -> (Self, Result<(), SessionError>) {
        let rx = Rc::new(RefCell::new(Pipe::default()));
        let wrote = Rc::new(RefCell::new(Vec::new()));
        let io = Scripted {
            rx: rx.clone(),
            wrote: wrote.clone(),
        };
        let link = RouterLink::with_params(io, role, &config(cookie), params(), 1).expect("a link");
        let client = link.with_client_role();
        match client {
            Ok(link) => (Self { link, rx, wrote }, Ok(())),
            Err(error) => {
                let io = Scripted {
                    rx: rx.clone(),
                    wrote: wrote.clone(),
                };
                let link = RouterLink::with_params(io, role, &config(cookie), params(), 1)
                    .expect("a link");
                (Self { link, rx, wrote }, Err(error))
            }
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

/// Writes the forwarded FRAMEs to the link: a batch at a time, a byte at a time, or everything at once.
fn write_frames(rig: &mut Rig, frames: &[Vec<u8>], mode: Mode) {
    match mode {
        Mode::Whole => {
            for frame in frames {
                rig.feed(&framed(frame));
                rig.settle();
            }
        }
        Mode::Bytewise => {
            for frame in frames {
                for byte in framed(frame) {
                    rig.feed(&[byte]);
                    rig.pump();
                }
                rig.settle();
            }
        }
        Mode::Coalesced => {
            let all: Vec<u8> = frames.iter().flat_map(|frame| framed(frame)).collect();
            rig.feed(&all);
            rig.settle();
        }
    }
}

// ----------------------------------------------------------------------------------------------- the scenarios

fn text(payload: &[u8]) -> String {
    assert_eq!(
        payload.get(..4),
        Some(&[0x00, 0x01, 0x00, 0x00][..]),
        "a CDR header"
    );
    let length = u32::from_le_bytes(payload[4..8].try_into().expect("a length")) as usize;
    assert_eq!(payload.len(), 8 + length, "a CDR string of its own length");
    String::from_utf8(payload[8..payload.len() - 1].to_vec()).expect("UTF-8 text")
}

fn run_session(run: &Run, mode_name: &str, mode: Mode) {
    let (mut rig, role) = Rig::new(Role::Connector, &[]);
    role.expect("a connector takes the client role");
    assert!(rig.link.session().is_client());
    let handle = rig.link.handle();
    rig.link.open(handle, 0).expect("the INIT_SYN is queued");
    rig.settle();
    rig.feed(&framed(&run.ack));
    rig.settle();
    rig.feed(&framed(&run.open_ack));
    rig.settle();
    assert_eq!(rig.link.session().state(), State::Open);
    rig.link
        .declare_subscriber(handle, SUBSCRIPTION, KEY)
        .expect("the subscription is queued");
    rig.settle();
    write_frames(&mut rig, &run.forwarded, mode);

    let written = rig.written();
    line(&std::format!(
        "sent {} {mode_name} {}",
        run.name,
        hex(&written)
    ));

    let mut delivered = 0usize;
    while let Some(notice) = rig.link.next_notice() {
        match notice {
            Notice::SampleDelivered(sample) => {
                delivered += 1;
                line(&std::format!(
                    "sample {} {mode_name} {} {} {} {}",
                    run.name,
                    sample.subscription,
                    sample.sequence,
                    sample.timestamp,
                    text(sample.payload()).replace(' ', "_")
                ));
            }
            Notice::Closed { .. } => panic!("the link closed before the owner asked"),
            _ => {}
        }
    }
    line(&std::format!(
        "pushes {} {mode_name} dropped={}",
        run.name,
        run.forwarded.len() - delivered
    ));

    let before = rig.written().len();
    rig.link.close(handle, 0).expect("a local close");
    rig.settle();
    let wrote = rig.written()[before..].to_vec();
    // The samples were taken above. What a close leaves behind is read from the link: the reason it reported, and any
    // sample it still holds. The `Closed` notice is the close itself and is not a sample.
    let mut reason = None;
    let mut samples_left = 0usize;
    while let Some(notice) = rig.link.next_notice() {
        match notice {
            Notice::Closed { reason: reported } => reason = Some(reported),
            Notice::SampleDelivered(_) | Notice::SampleStored(_) => samples_left += 1,
            _ => {}
        }
    }
    let reason = reason.expect("a local close reports its reason");
    let subscription = match rig.link.session().subscriber_id() {
        Some(id) => std::format!("{id}"),
        None => String::from("none"),
    };
    line(&std::format!(
        "closed {} {mode_name} reason={reason} wrote={} queue={samples_left} subscription={subscription}",
        run.name,
        hex(&wrote)
    ));
    line(&std::format!("ok {}-{mode_name}", run.name));
}

/// Where a forwarded FRAME's Put header lies, and where its timestamp's ID length lies.
fn put_offsets(frame: &[u8]) -> (usize, usize) {
    let key = KEY.as_bytes();
    let put = frame
        .windows(key.len())
        .position(|window| window == key)
        .expect("the chatter key")
        + key.len();
    let mut at = put + 1;
    while frame[at] & 0x80 != 0 {
        at += 1;
    }
    (put, at + 1)
}

#[test]
fn the_router_link_exam() {
    let Some(runs) = runs() else {
        return;
    };
    for run in &runs {
        line(&std::format!(
            "fed {} {} {} {}",
            run.name,
            hex(&run.ack),
            hex(&run.open_ack),
            run.forwarded
                .iter()
                .map(|frame| hex(frame))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        for (mode_name, mode) in MODES {
            run_session(run, mode_name, mode);
        }
    }

    let bounds: Bounds = params().bounds;
    let frame = &runs[0].forwarded[0];

    // The plain decoder, with no client role, refuses the timestamp of a Put.
    let refusal =
        decode_batch_with(frame, &bounds).expect_err("a plain decoder takes no timestamp");
    line(&std::format!(
        "refused default-decoder-takes-a-timestamp {}",
        refusal.name()
    ));

    // The client decoder takes the timestamp only with a 16-byte ID.
    let (put, id_length) = put_offsets(frame);
    let mut short = frame.clone();
    short[id_length] = 15;
    let refusal = decode_batch_client(&short, &bounds, false).expect_err("a short ID is malformed");
    line(&std::format!(
        "refused client-decoder-takes-a-short-id {}",
        refusal.name()
    ));

    // The encoding flag is refused for every session, the client's included.
    let mut encoded = frame.clone();
    encoded[put] |= 0x40;
    let refusal =
        decode_batch_client(&encoded, &bounds, false).expect_err("an encoding is not taken");
    line(&std::format!(
        "refused client-decoder-takes-an-encoding {}",
        refusal.name()
    ));

    // A link built as a listener cannot take the role.
    let (_, role) = Rig::new(Role::Listener, &[0xc0; 8]);
    let error = role.expect_err("a listener takes no client role");
    assert_eq!(error, SessionError::InvalidConfig);
    line("refused client-link-as-a-listener invalid-config");

    // The client decoder takes what the router forwarded, and `Session` is the type that reads it.
    let _: Option<Session> = None;
    for run in &runs {
        for frame in &run.forwarded {
            assert!(decode_batch_client(frame, &bounds, false).is_ok());
        }
    }
}
