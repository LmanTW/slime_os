//! The stack exam: the sizes of the parts the Zenoh service keeps in its main frame, and the depth of the calls it makes
//! below it, at the size the component is built for and at a larger stated size. `scripts/check/check-zenoh-profile0.py
//! --slice service-stack` runs it, and `scripts/lib/zenoh_stack_exam.py` owns what the printed lines must be.
//!
//! The test restates what `components/services/zenoh-service/src/main.rs` declares: the `Link` type, the arrays of
//! `main` and `read_grants`, and the core's parameters. The judge binds the restatement to `main.rs` through the link
//! parameters and the array names that this test prints.
//!
//! The depth of a call path is measured by painting the free stack below the caller, running the path, and reading how
//! far the paint was overwritten. A frame of a known size calibrates the method first. The test runs on a thread
//! whose stack it owns, in the profile the test run uses, and prints that profile.

use crate::zenoh_link::{ByteLink, LinkError, LinkHandle, LinkOf};
use crate::zenoh_node::{Connection, Reply, Stream};
use crate::zenoh_profile0::Bounds;
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::session::{Params, Role};
use crate::zenoh_service::{Core, OverLink, Row};
use crate::zenoh_service_link::pair::{Io, Pipe, cfg};
use crate::zenoh_service_server::Server;
use core::hint::black_box;
use slime_proto::zenoh_service_client as wire;
use slime_proto::zenoh_service_client_wire::WireServiceRequest;
use slime_proto::zenoh_service_grants_table_wire as grants;
use slime_proto::zenoh_service_limits_wire as limits_wire;
use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;

const PAINT_BYTES: usize = 128 * 1024;
const PAINT_BYTE: u8 = 0xa5;
const CALIBRATION_BYTES: usize = 8192;
const THREAD_STACK_BYTES: usize = 2 * 1024 * 1024;
const GID: [u8; 16] = [0xe0; 16];
const KEYS: [&str; 2] = ["0/slime_stack/telemetry", "0/slime_stack/command"];

// The `Link` alias of the component: `LinkOf<Stream<Wire<'a, 'b>>, 514, 2, 5, 129, PAYLOAD, 8, 4>`.
const FRAMED: usize = 514;
const ALIASES: usize = 2;
const SUBSCRIBERS: usize = 5;
const KEY_BYTES: usize = 129;
const NOTICES: usize = 8;
const EVENTS: usize = 4;
const SLOTS: usize = 4;
const PAGE_ROWS: usize = 6;

type Link<'a, 'b, const P: usize> =
    LinkOf<Stream<Wire<'a, 'b>>, FRAMED, ALIASES, SUBSCRIBERS, KEY_BYTES, P, NOTICES, EVENTS>;
type Far<const P: usize> = LinkOf<Io, FRAMED, ALIASES, SUBSCRIBERS, KEY_BYTES, P, NOTICES, EVENTS>;

/// The component's `Wire`: two references, as `Wire { io, connection }` holds in `main.rs`.
struct Wire<'a, 'b> {
    io: &'a mut Io,
    _connection: &'b u8,
}

impl Connection for Wire<'_, '_> {
    fn send(&mut self, bytes: &[u8]) -> Result<Reply, LinkError> {
        let sent = self.io.send(bytes)?;
        Ok(done(sent))
    }

    fn recv(&mut self, bytes: &mut [u8]) -> Result<Reply, LinkError> {
        let read = self.io.recv(bytes)?;
        Ok(done(read))
    }
}

fn done(transferred: usize) -> Reply {
    Reply {
        success: true,
        status: 0,
        transferred: transferred as u64,
        end_of_stream: false,
    }
}

/// Fills the stack below the caller and returns the lowest painted address.
#[inline(never)]
fn paint() -> usize {
    let mut buffer = [PAINT_BYTE; PAINT_BYTES];
    black_box(&mut buffer);
    buffer.as_ptr() as usize
}

/// The lowest address of the painted stack that something wrote to.
#[inline(never)]
fn lowest_written(start: usize) -> usize {
    let mut at = start;
    while at < start + PAINT_BYTES {
        // SAFETY: `at` lies inside the buffer that `paint` filled. That buffer is part of this thread's stack, which
        // stays mapped. Its contents are dead, so a read of it only observes the paint or a later write.
        if unsafe { core::ptr::read_volatile(at as *const u8) } != PAINT_BYTE {
            break;
        }
        at += 1;
    }
    at
}

/// Runs `work` with the stack below this frame painted, and returns how many bytes it reached below the paint's top.
#[inline(never)]
fn measure<F: FnOnce()>(work: F) -> usize {
    let start = paint();
    work();
    let lowest = lowest_written(start);
    assert!(
        lowest > start + 1024,
        "the call path used the whole painted stack"
    );
    start + PAINT_BYTES - lowest
}

#[inline(never)]
fn calibration_frame() {
    let mut frame = [0u8; CALIBRATION_BYTES];
    black_box(&mut frame);
}

fn request(op: i64, row: u16, sequence: i64) -> [u8; 32] {
    WireServiceRequest {
        magic: wire::SERVICE_MAGIC as u32,
        version: wire::FORMAT_VERSION as u16,
        op: op as u8,
        flags: 0,
        row,
        reserved: [0; 2],
        sequence,
        reserved2: [0; 12],
    }
    .encode()
}

fn line(text: &str) {
    println!("[zenoh-exam] stack {text}");
}

/// The component's parameters, with the payload the size states.
fn params(payload: usize) -> Params {
    Params {
        bounds: Bounds {
            payload,
            ..Bounds::DEMO
        },
        local: 3,
        per_side: 2,
        events: EVENTS,
        aliases: ALIASES,
        ..Params::DEMO
    }
}

/// The size of the arrays that `main` and `read_grants` hold for `holders` holders and `rows` rows.
fn locals(holders: usize, rows: usize) -> usize {
    limits_wire::RECORD_LEN
        + grants::HEADER_BYTES
        + rows * grants::ENTRY_BYTES
        + holders * grants::HOLDER_NAME_BYTES
        + holders * size_of::<usize>()
        + rows * grants::MAX_KEY_BYTES
        + rows * size_of::<usize>()
        + rows * size_of::<(usize, bool, bool)>()
        + PAGE_ROWS * grants::ENTRY_BYTES
}

/// One size: the parts, the frames, and the deepest call path of a service that attaches its holders, declares its
/// subscriptions, publishes, receives a sample from the peer and serves a take.
fn size<const H: usize, const P: usize, const R: usize>(
    label: &str,
    rows: [Row<'static>; R],
    peer_rows: usize,
) {
    let sizes = Core::<'static, H, SLOTS, P, R>::sizes();
    let ab = Rc::new(RefCell::new(Pipe::default()));
    let ba = Rc::new(RefCell::new(Pipe::default()));
    let mut io = Io {
        rx: ab.clone(),
        tx: ba.clone(),
    };
    let connection = 0u8;
    let mut svc: Link<'_, '_, P> = LinkOf::with_params(
        Stream::new(Wire {
            io: &mut io,
            _connection: &connection,
        }),
        Role::Listener,
        &cfg(&[0xb2; 8], &[0xc0; 32], 7000),
        params(P),
        1,
    )
    .expect("service");
    let mut peer: Far<P> = LinkOf::with_params(
        Io { rx: ba, tx: ab },
        Role::Connector,
        &cfg(&[0xa1; 8], b"", 9000),
        Params {
            local: 2,
            per_side: 3,
            ..params(P)
        },
        1,
    )
    .expect("peer");
    let mut core =
        Core::<'static, H, SLOTS, P, R>::new(&rows, GID, &params(P)).expect("the grants");
    let mut over = OverLink::<'static, P>::new();
    let mut server = Server::<H>::new();
    let (hs, hp): (LinkHandle, LinkHandle) = (svc.handle(), peer.handle());
    let mut page = [0u8; 4096];
    let mut depth = 0usize;
    let mut now = 0u64;

    macro_rules! measured {
        ($body:block) => {
            depth = depth.max(measure(|| $body))
        };
    }
    // One pass of the service's loop: pump, route what arrived, settle, and declare what is left.
    macro_rules! iteration {
        () => {
            now += 1;
            measured!({
                let _ = svc.pump(hs, now);
                let _ = core.drain_notices(&mut svc);
                let _ = over.settle(&mut core, &svc);
                while over.declare_next(&mut core, &mut svc, hs).unwrap_or(false) {
                    let _ = svc.pump(hs, now);
                    let _ = over.settle(&mut core, &svc);
                }
            });
            peer.pump(hp, now).expect("pump the peer");
        };
    }

    peer.open(hp, 0).expect("open");
    for _ in 0..12 {
        iteration!();
        if peer.is_open() && svc.is_open() {
            break;
        }
    }
    assert!(peer.is_open() && svc.is_open());
    for _ in 0..10 {
        iteration!();
    }
    let attach = request(wire::OP_ATTACH, 0, 0);
    for holder in 0..H {
        measured!({
            let _ = server.control(&core, holder, &attach);
        });
    }
    peer.declare_subscriber(hp, 1, KEYS[0])
        .expect("the peer declares");
    for _ in 0..6 {
        iteration!();
    }
    while peer.next_notice().is_some() {}
    let publish = request(wire::OP_PUBLISH, 0, 5);
    let payload = [7u8; P];
    now += 1;
    measured!({
        let _ = server.request(
            &mut core, &mut over, &mut svc, hs, 0, &publish, &payload, &mut page, 100, now,
        );
    });
    for _ in 0..4 {
        iteration!();
    }
    let attachment = encode::attachment(9, 1009, &GID).expect("attachment");
    peer.publish(hp, KEYS[0], &attachment, &payload)
        .expect("the peer queues");
    for _ in 0..4 {
        iteration!();
    }
    let take = request(wire::OP_TAKE, 0, 0);
    for _ in 0..3 {
        now += 1;
        measured!({
            let _ = server.request(
                &mut core,
                &mut over,
                &mut svc,
                hs,
                peer_rows,
                &take,
                &[],
                &mut page,
                100,
                now,
            );
        });
    }
    let detach = request(wire::OP_DETACH, 0, 0);
    for holder in 0..H {
        measured!({
            let _ = server.control(&core, holder, &detach);
        });
    }

    line(&format!("config {label} {H} {SLOTS} {P} {R}"));
    line(&format!(
        "link {label} {FRAMED}, {ALIASES}, {SUBSCRIBERS}, {KEY_BYTES}, {P}, {NOTICES}, {EVENTS}"
    ));
    line(&format!(
        "frame {label} record object names name_lens keys key_lens stored page"
    ));
    line(&format!("size {label} slot {}", sizes.slot));
    line(&format!("size {label} row {}", sizes.row));
    line(&format!("size {label} holder {}", sizes.holder));
    line(&format!("size {label} fixed {}", sizes.fixed));
    line(&format!(
        "size {label} core {}",
        size_of::<Core<'static, H, SLOTS, P, R>>()
    ));
    line(&format!(
        "size {label} link {}",
        size_of::<Link<'static, 'static, P>>()
    ));
    line(&format!(
        "size {label} over {}",
        size_of::<OverLink<'static, P>>()
    ));
    line(&format!("size {label} server {}", size_of::<Server<H>>()));
    line(&format!("size {label} locals {}", locals(H, R)));
    line(&format!("depth {label} {depth}"));
}

/// The rows of the composition `sel4-zenoh-service-four`, which the component is built for. `alpha` publishes the exchange key.
/// `beta` subscribes to it. `gamma` and `delta` each hold the command key as row 0 and the exchange key as row 1.
fn rows_built() -> [Row<'static>; 6] {
    let row = |holder, key: usize, publish, subscribe| Row {
        holder,
        key: KEYS[key],
        publish,
        subscribe,
    };
    [
        row(0, 0, true, false),
        row(1, 0, false, true),
        row(2, 1, false, true),
        row(2, 0, false, true),
        row(3, 1, false, true),
        row(3, 0, false, true),
    ]
}

/// The sensor publishes telemetry. The controller subscribes to it and publishes a command. The actuator subscribes to
/// the command. The supervisor subscribes to both.
fn rows_stated() -> [Row<'static>; 6] {
    let row = |holder, key: usize, publish, subscribe| Row {
        holder,
        key: KEYS[key],
        publish,
        subscribe,
    };
    [
        row(0, 0, true, false),
        row(1, 0, false, true),
        row(1, 1, true, false),
        row(2, 1, false, true),
        row(3, 0, false, true),
        row(3, 1, false, true),
    ]
}

fn exam() {
    line(&format!("arch {}", std::env::consts::ARCH));
    line(&format!(
        "profile {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    ));
    let calibration = measure(calibration_frame);
    line(&format!("calibration {CALIBRATION_BYTES} {calibration}"));
    size::<4, 12, 6>("built", rows_built(), 1);
    size::<4, 64, 6>("stated", rows_stated(), 0);
}

#[test]
fn the_stack_exam() {
    let result = std::thread::Builder::new()
        .stack_size(THREAD_STACK_BYTES)
        .spawn(exam)
        .expect("a thread")
        .join();
    if let Err(error) = result {
        let text: String = error
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| error.downcast_ref::<&str>().map(|text| (*text).into()))
            .unwrap_or_default();
        panic!("the stack exam failed: {text}");
    }
}
