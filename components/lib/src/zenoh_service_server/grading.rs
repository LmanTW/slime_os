//! The grading exam: the server driven through a second run, a malformed request and a stalled link, printing one
//! `[zenoh-exam] grading ...` line for each answer and for the state it left. `scripts/check/check-zenoh-profile0.py
//! --slice grading` owns what those lines must be, and `scripts/lib/zenoh_grading_exam.py` owns every byte of them.
//!
//! The setup is the server exam's: three holders, two ring slots of twelve bytes, and the same four rows. A run
//! builds its own server, core, link and peer. The stream under the service's link counts the bytes it accepts and
//! the offers it refuses, and may be set to refuse every offer or to accept one byte in two.

use super::exam::{GID, Holders, KEYS, PAGE, START, hex, params, request, rows};
use super::{Answer, PUMP_BOUND, Server};
use crate::zenoh_link::{ByteLink, LinkError, LinkHandle, LinkOf, MAX_RETRIES, Notice};
use crate::zenoh_profile0::session::{Params, Role};
use crate::zenoh_service::OverLink;
use crate::zenoh_service_link::pair::{Far, Io, Pipe, cfg};
use slime_proto::zenoh_service_client as wire;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::string::String;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Dead,
    Slow,
}

struct Meter {
    inner: Io,
    mode: Rc<Cell<Mode>>,
    written: Rc<Cell<usize>>,
    refused: Rc<Cell<u32>>,
    offers: Rc<Cell<u32>>,
}

impl ByteLink for Meter {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let take = match self.mode.get() {
            Mode::Normal => buf.len(),
            Mode::Dead => 0,
            Mode::Slow => {
                let offer = self.offers.get();
                self.offers.set(offer + 1);
                usize::from(offer.is_multiple_of(2)).min(buf.len())
            }
        };
        if take == 0 && self.mode.get() != Mode::Normal {
            self.refused.set(self.refused.get() + 1);
            return Ok(0);
        }
        let taken = self.inner.send(&buf[..take])?;
        self.written.set(self.written.get() + taken);
        Ok(taken)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        self.inner.recv(buf)
    }

    fn eof(&self) -> bool {
        false
    }
}

type Near = LinkOf<Meter, 514, 1, 5, 129, 12, 8, 4>;

struct World {
    server: Server<3>,
    core: Holders,
    over: OverLink<'static, 12>,
    link: Near,
    peer: Far,
    handle: LinkHandle,
    peer_handle: LinkHandle,
    tick: u64,
    mode: Rc<Cell<Mode>>,
    written: Rc<Cell<usize>>,
    refused: Rc<Cell<u32>>,
    offers: Rc<Cell<u32>>,
}

impl World {
    fn new() -> Self {
        let ab = Rc::new(RefCell::new(Pipe::default()));
        let ba = Rc::new(RefCell::new(Pipe::default()));
        let mode = Rc::new(Cell::new(Mode::Normal));
        let written = Rc::new(Cell::new(0));
        let refused = Rc::new(Cell::new(0));
        let offers = Rc::new(Cell::new(0));
        let peer_params = Params {
            local: 2,
            per_side: 3,
            ..params()
        };
        let mut link = Near::with_params(
            Meter {
                inner: Io {
                    rx: ab.clone(),
                    tx: ba.clone(),
                },
                mode: mode.clone(),
                written: written.clone(),
                refused: refused.clone(),
                offers: offers.clone(),
            },
            Role::Listener,
            &cfg(&[0xb2; 8], &[0xc0; 32], 7000),
            params(),
            1,
        )
        .expect("service");
        let mut peer = Far::with_params(
            Io { rx: ba, tx: ab },
            Role::Connector,
            &cfg(&[0xa1; 8], b"", 9000),
            peer_params,
            1,
        )
        .expect("peer");
        let (handle, peer_handle) = (link.handle(), peer.handle());
        peer.open(peer_handle, 0).expect("open");
        for tick in 1..=12u64 {
            peer.pump(peer_handle, tick).expect("pump the peer");
            link.pump(handle, tick).expect("pump the service");
            if peer.is_open() && link.is_open() {
                break;
            }
        }
        assert!(peer.is_open() && link.is_open());
        written.set(0);
        Self {
            server: Server::new(),
            core: Holders::new(&rows(), GID, &params()).expect("the grants"),
            over: OverLink::new(),
            link,
            peer,
            handle,
            peer_handle,
            tick: 100,
            mode,
            written,
            refused,
            offers,
        }
    }

    /// The peer declares `key` as subscriber `id`, and both links run until the declaration arrives.
    fn peer_declares(&mut self, id: u32, key: &str) {
        self.peer
            .declare_subscriber(self.peer_handle, id, key)
            .expect("the peer declares");
        for _ in 0..3 {
            self.tick += 1;
            self.peer
                .pump(self.peer_handle, self.tick)
                .expect("pump the peer");
            self.link
                .pump(self.handle, self.tick)
                .expect("pump the service");
        }
        while self.link.next_notice().is_some() {}
        while self.peer.next_notice().is_some() {}
        self.written.set(0);
    }

    /// The samples the peer received since the last call. The peer is only observed, so a pump it refuses counts for
    /// nothing.
    fn peer_samples(&mut self) -> usize {
        for _ in 0..3 {
            self.tick += 1;
            let _ = self.peer.pump(self.peer_handle, self.tick);
        }
        let mut samples = 0;
        while let Some(notice) = self.peer.next_notice() {
            if matches!(notice, Notice::SampleDelivered(_)) {
                samples += 1;
            }
        }
        samples
    }

    fn state(&mut self) -> String {
        let wrote = usize::from(self.written.replace(0) > 0);
        let peer = usize::from(self.peer_samples() > 0);
        let mut rings = [(0usize, 0u32); 2];
        for (holder, ring) in rings.iter_mut().enumerate() {
            *ring = self.core.held(holder).expect("a ring");
        }
        let attached: usize = (0..3)
            .filter(|holder| self.server.attached(*holder))
            .map(|holder| 1 << holder)
            .sum();
        format!(
            "rings {}/{},{}/{} wrote {wrote} peer {peer} refused {} link {} attached {attached}",
            rings[0].0,
            rings[0].1,
            rings[1].0,
            rings[1].1,
            self.refused.get(),
            if self.link.is_open() {
                "open"
            } else {
                "closed"
            },
        )
    }

    fn say(
        &mut self,
        phase: &str,
        label: &str,
        holder: usize,
        path: &str,
        sent: &[u8],
        answer: &Answer,
        page: &[u8],
    ) {
        let state = self.state();
        println!(
            "[zenoh-exam] grading {phase} {label} {holder} {path} request {} completion {} page {} {state}",
            dash(sent),
            hex(&answer.completion),
            dash(&page[..answer.page_len]),
        );
    }

    fn control(&mut self, phase: &str, label: &str, holder: usize, sent: &[u8]) {
        let answer = self.server.control(&self.core, holder, sent);
        self.say(phase, label, holder, "control", sent, &answer, &[]);
    }

    fn ring(&mut self, phase: &str, label: &str, holder: usize, sent: &[u8], payload: &[u8]) {
        self.tick += 1;
        let mut page = [0u8; PAGE];
        let answer = self.server.request(
            &mut self.core,
            &mut self.over,
            &mut self.link,
            self.handle,
            holder,
            sent,
            payload,
            &mut page,
            START,
            self.tick,
        );
        self.say(phase, label, holder, "ring", sent, &answer, &page);
    }

    /// Closes the link and gives it the pumps the service gives it to flush its CLOSE.
    fn close(&mut self, phase: &str) {
        self.link.close(self.handle, 0).expect("close the link");
        for _ in 0..PUMP_BOUND {
            self.tick += 1;
            self.link
                .pump(self.handle, self.tick)
                .expect("flush the close");
            if !self.link.send_pending() {
                break;
            }
        }
        let state = self.state();
        println!(
            "[zenoh-exam] grading {phase} link-close - service request - completion - page - {state}"
        );
    }
}

fn dash(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::from("-")
    } else {
        hex(bytes)
    }
}

fn patched(mut bytes: [u8; 32], at: usize, value: u8) -> [u8; 32] {
    bytes[at] = value;
    bytes
}

/// Two holders attach, one publishes on its second row, each takes, both detach, and the link closes.
fn boot(phase: &str) {
    let mut world = World::new();
    let attach = request(wire::OP_ATTACH, 0, 0);
    for holder in [0usize, 1] {
        world.control(phase, "attach", holder, &attach);
    }
    world.peer_declares(1, KEYS[1]);
    world.ring(
        phase,
        "publish",
        0,
        &request(wire::OP_PUBLISH, 1, 5),
        &[9, 8],
    );
    let take = request(wire::OP_TAKE, 0, 0);
    for holder in [0usize, 1] {
        world.ring(phase, "take", holder, &take, &[]);
    }
    let detach = request(wire::OP_DETACH, 0, 0);
    for holder in [1usize, 0] {
        world.control(phase, "detach", holder, &detach);
    }
    world.control(phase, "attach-after-detach", 0, &attach);
    world.ring(phase, "take-after-detach", 1, &take, &[]);
    world.close(phase);
}

/// Requests outside the protocol, on the ring and on the control endpoint, after one publication sits in both rings.
fn malformed() {
    let phase = "malformed";
    let mut world = World::new();
    let attach = request(wire::OP_ATTACH, 0, 0);
    for holder in [0usize, 1] {
        let _ = world.server.control(&world.core, holder, &attach);
    }
    world.peer_declares(1, KEYS[1]);
    world.ring(
        phase,
        "preload",
        0,
        &request(wire::OP_PUBLISH, 1, 5),
        &[9, 8],
    );

    let good = request(wire::OP_PUBLISH, 1, 9);
    let ring = [
        ("publish-short", 0usize, &good[..31], 0),
        ("publish-long", 0, &[&good[..], &[0u8][..]].concat()[..], 0),
        ("publish-empty", 0, &[][..], 0),
    ];
    for (label, holder, bytes, _) in ring {
        world.ring(phase, label, holder, bytes, &[]);
    }
    for (label, at, value) in [
        ("publish-magic", 0, 0),
        ("publish-version", 4, 2),
        ("publish-flags", 7, 1),
        ("publish-reserved", 10, 1),
        ("publish-reserved2", 20, 1),
    ] {
        world.ring(phase, label, 0, &patched(good, at, value), &[]);
    }
    world.ring(
        phase,
        "publish-row-past-rows",
        0,
        &request(wire::OP_PUBLISH, 2, 9),
        &[],
    );
    world.ring(
        phase,
        "publish-row-far-past-rows",
        0,
        &request(wire::OP_PUBLISH, 9, 9),
        &[],
    );
    world.ring(phase, "take-row", 1, &request(wire::OP_TAKE, 2, 0), &[]);
    world.ring(
        phase,
        "take-sequence",
        1,
        &request(wire::OP_TAKE, 0, 5),
        &[],
    );
    for (label, op) in [
        ("operation-zero", 0),
        ("operation-six", 6),
        ("operation-255", 255),
    ] {
        world.ring(phase, label, 0, &patched(good, 6, op), &[]);
    }
    world.ring(phase, "attach-on-the-ring", 0, &attach, &[]);
    world.ring(
        phase,
        "detach-on-the-ring",
        0,
        &request(wire::OP_DETACH, 0, 0),
        &[],
    );
    world.ring(
        phase,
        "publish-magic-unattached",
        2,
        &patched(good, 0, 0),
        &[],
    );
    world.control(phase, "attach-short", 1, &attach[..31]);
    world.control(phase, "attach-long", 1, &[&attach[..], &[0u8][..]].concat());
    world.control(phase, "attach-magic", 1, &patched(attach, 0, 0));
    world.control(phase, "attach-flags", 1, &patched(attach, 7, 1));
    world.control(phase, "attach-sequence", 1, &request(wire::OP_ATTACH, 0, 7));
    world.control(phase, "attach-row", 1, &request(wire::OP_ATTACH, 1, 0));
    world.control(phase, "detach-sequence", 0, &request(wire::OP_DETACH, 0, 3));
    world.control(phase, "abort-row", 0, &request(wire::OP_ABORT, 2, 0));
    world.control(phase, "publish-on-control", 0, &good);
    world.control(phase, "take-on-control", 0, &request(wire::OP_TAKE, 0, 0));

    let take = request(wire::OP_TAKE, 0, 0);
    for holder in [0usize, 1] {
        world.ring(phase, "take-after", holder, &take, &[]);
    }
    world.ring(
        phase,
        "publish-after",
        0,
        &request(wire::OP_PUBLISH, 1, 9),
        &[9, 8],
    );
}

/// A publication the stream does not take. No ring and no peer holds the sample when the holder is told.
fn stall(phase: &str, mode: Mode) {
    let mut world = World::new();
    let attach = request(wire::OP_ATTACH, 0, 0);
    for holder in [0usize, 1] {
        world.control(phase, "attach", holder, &attach);
    }
    world.peer_declares(1, KEYS[1]);
    world.offers.set(0);
    world.mode.set(mode);
    world.ring(phase, "publish", 0, &request(wire::OP_PUBLISH, 1, 20), &[1]);
    world.ring(phase, "take", 1, &request(wire::OP_TAKE, 0, 0), &[]);
    world.control(phase, "detach", 0, &request(wire::OP_DETACH, 0, 0));
}

pub fn run() {
    println!("[zenoh-exam] grading constants pump-bound {PUMP_BOUND} max-retries {MAX_RETRIES}");
    boot("boot-1");
    malformed();
    stall("stall-dead", Mode::Dead);
    stall("stall-slow", Mode::Slow);
    boot("boot-2");
    println!("[zenoh-exam] grading ok second-boot-malformed-and-stall");
}
