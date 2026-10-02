#![no_std]
#![no_main]

//! The demo's subscriber node: a Zenoh Profile 0 listener that declares the demo
//! key, validates each received `Counter` sample, and tears the session down by
//! undeclaring before it closes.

use slime_components::network_io::{
    Connection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::ros_cdr::Counter;
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::{ByteLink, Link, LinkError, LinkHandle, Notice};
use slime_components::zenoh_profile0::session::{Config, Role};
use slime_proto::network_service as net;
use slime_rt::{
    debug_write, exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now,
};

slime_rt::entry!(main);

const ADDRESS: [u8; 4] = [127, 0, 0, 1];
const PORT: u16 = 7447;
const RING_BASE: u64 = 0x0000_001c_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const DEADLINE_MS: i64 = 20_000;
const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const EXPECTED: [(u32, i32); 4] = [(0, 10), (1, 20), (2, 30), (3, 40)];
const ZID: [u8; 8] = [0xb2; 8];
const COOKIE: &[u8] = b"slime-zenoh-profile-0";
const LEASE_MS: u64 = 2000;
const LINE_BYTES: usize = 128;
const WHO: &[u8] = b"[ros2-demo-subscriber] ";
const SUMMARY: &[u8] = b"[rpi5-ros2-demo] received count=4 sequences=0,1,2,3 values=10,20,30,40\n";

/// The service connection seen as a byte stream; every call is non-blocking so the link owns backpressure.
struct Stream<'a, 'b> {
    io: &'a mut NetworkIo<'b>,
    connection: &'a Connection,
    eof: bool,
}

impl ByteLink for Stream<'_, '_> {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        let reply = self
            .io
            .send_nonblocking(self.connection, buf)
            .map_err(|_| LinkError::Reset)?;
        step(&reply, buf.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        let reply = self
            .io
            .recv_nonblocking(self.connection, buf)
            .map_err(|_| LinkError::Reset)?;
        if reply.is_success() && reply.transferred == 0 && reply.flags == net::FLAG_END_OF_STREAM {
            self.eof = true;
            return Ok(0);
        }
        step(&reply, buf.len())
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

fn step(reply: &NetworkReply, offered: usize) -> Result<usize, LinkError> {
    if reply.is_success() {
        let moved = reply.transferred as usize;
        return if moved <= offered {
            Ok(moved)
        } else {
            Err(LinkError::Reset)
        };
    }
    match reply.status_detail {
        net::STATUS_WOULD_BLOCK => Ok(0),
        net::STATUS_RESET => Err(LinkError::Reset),
        _ => Err(LinkError::Closed),
    }
}

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:zenoh-network-request+signal"),
        completion_wait: binding(b"notification:zenoh-subscriber-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this
    // adapter, and the two declared endpoints belong to the same service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-subscriber-control"),
            binding(b"zenoh-subscriber-provision"),
            RING_BASE,
            DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|_| fail(b"attach"));

    refused(io.listen_ipv4(ADDRESS, PORT + 1), net::STATUS_DENIED);
    refused(io.connect_ipv4(ADDRESS, PORT), net::STATUS_DENIED);
    marker_denial(b"connect");

    let listener = io
        .listen_ipv4(ADDRESS, PORT)
        .unwrap_or_else(|_| fail(b"listen request"))
        .take_listener()
        .unwrap_or_else(|| fail(b"listen"));
    let connection = loop {
        let mut reply = io
            .accept(&listener)
            .unwrap_or_else(|_| fail(b"accept request"));
        if let Some(connection) = reply.take_connection() {
            break connection;
        }
        if reply.status_detail != net::STATUS_WOULD_BLOCK {
            fail(b"accept status");
        }
        bounded_yield(&clock);
    };

    let config = Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: 0,
        cookie: COOKIE,
    };
    let link = Link::new(
        Stream {
            io: &mut io,
            connection: &connection,
            eof: false,
        },
        Role::Listener,
        &config,
        1,
    )
    .unwrap_or_else(|_| fail(b"session config"));
    run(link, &clock);

    if !io
        .close(connection)
        .unwrap_or_else(|_| fail(b"close request"))
        .is_success()
        || !io
            .close_listener(listener)
            .unwrap_or_else(|_| fail(b"listener close request"))
            .is_success()
    {
        fail(b"close");
    }
    io.finish().unwrap_or_else(|_| fail(b"finish"));
    debug_write(b"[rpi5-ros2-demo] success profile=rpi5-ros2-demo-v2 samples=4\n");
    exit(0)
}

fn run(mut link: Link<Stream<'_, '_>>, clock: &TickClock) {
    let handle = link.handle();
    let mut received = 0usize;
    let mut declared = false;
    let mut undeclared = false;
    let mut closing = false;
    loop {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read"))) as u64;
        if link.pump(handle, now).is_err() {
            fail(b"link");
        }
        while let Some(notice) = link.next_notice() {
            match notice {
                Notice::HandshakeComplete => {
                    line(b"session open role=listener initial_sn=0 lease_ms=2000\n");
                }
                Notice::SampleDelivered(sample) => {
                    write_wire_line(b"wire received", received, link.last_received_batch());
                    validate(&sample, received);
                    received += 1;
                }
                Notice::SubscriberUndeclared { .. } => undeclared = true,
                Notice::Closed { .. } => return,
                Notice::SubscriberDeclared { .. } => {}
            }
        }
        if link.is_open() && !declared && !link.send_pending() {
            link.declare_subscriber(handle, 1, KEY)
                .unwrap_or_else(|_| fail(b"declare"));
            declared = true;
            line_key(b"declared subscriber id=1 key=");
        }
        if received == EXPECTED.len() && declared && !undeclared && !link.send_pending() {
            teardown(&mut link, handle);
            undeclared = true;
        }
        if undeclared && !closing && !link.send_pending() {
            debug_write(SUMMARY);
            line(b"undeclared subscriber id=1\n");
            line(b"session closing samples=4\n");
            link.close(handle, 0).unwrap_or_else(|_| fail(b"close"));
            closing = true;
        }
        if closing && !link.send_pending() {
            return;
        }
        bounded_yield(clock);
    }
}

/// Undeclares the subscription; the session closes only after this frame is sent.
fn teardown(link: &mut Link<Stream<'_, '_>>, handle: LinkHandle) {
    link.undeclare_subscriber(handle, 1, KEY)
        .unwrap_or_else(|_| fail(b"undeclare"));
}

fn validate(sample: &slime_components::zenoh_link::Sample, index: usize) {
    let Some(&(sequence, value)) = EXPECTED.get(index) else {
        fail(b"unexpected sample");
    };
    let counter = Counter::decode(sample.payload()).unwrap_or_else(|_| fail(b"cdr decode"));
    if counter.sequence != sequence || counter.value != value {
        fail(b"sample value");
    }
    let mut message = [0u8; 64];
    let mut at = 0;
    for part in [
        b"sample validated sequence=".as_slice(),
        digits(u64::from(sequence)).as_slice(),
        b" value=".as_slice(),
        digits(value as u64).as_slice(),
        b"\n".as_slice(),
    ] {
        if let (Some(dst), true) = (message.get_mut(at..at + part.len()), at + part.len() <= 64) {
            dst.copy_from_slice(part);
            at += part.len();
        }
    }
    line(message.get(..at).unwrap_or(&[]));
}

/// Writes `[who] <what> sample=<n> hex=<batch>` as one console message so the line cannot
/// be interleaved with the other node's output.
fn write_wire_line(what: &[u8], index: usize, batch: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 640];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        for byte in bytes {
            if let Some(slot) = out.get_mut(at) {
                *slot = *byte;
                at += 1;
            }
        }
    };
    put(WHO);
    put(what);
    put(b" sample=");
    put(&[b'0' + (index % 10) as u8]);
    put(b" hex=");
    for byte in batch {
        put(&[
            DIGITS[usize::from(byte >> 4)],
            DIGITS[usize::from(byte & 0x0f)],
        ]);
    }
    put(b"\n");
    debug_write(out.get(..at).unwrap_or(&[]));
}

fn refused(reply: Result<NetworkReply, NetworkError>, expected: i32) {
    let reply = reply.unwrap_or_else(|_| fail(b"authority request transport"));
    if reply.status_detail != expected
        || reply.transferred != 0
        || reply.capability_kind != net::CAPABILITY_NONE
        || reply.capability != 0
    {
        fail(b"authority refusal result");
    }
}

fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
}

fn bounded_yield(clock: &TickClock) {
    if clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read"))) >= DEADLINE_MS {
        fail(b"deadline");
    }
    yield_now();
}

/// Writes `[who] <message>` as one console message, so another component's output cannot split the line.
fn line(message: &[u8]) {
    let mut out = [0u8; LINE_BYTES];
    let mut at = 0;
    for part in [WHO, message] {
        let room = out.len() - at;
        let take = part.len().min(room);
        if let (Some(dst), Some(src)) = (out.get_mut(at..at + take), part.get(..take)) {
            dst.copy_from_slice(src);
            at += take;
        }
    }
    debug_write(out.get(..at).unwrap_or(&[]));
}

fn marker_denial(class: &[u8]) {
    let mut message = [0u8; 64];
    let mut at = 0;
    for part in [
        b"denial class=".as_slice(),
        class,
        b" refused=1\n".as_slice(),
    ] {
        if let (Some(dst), true) = (message.get_mut(at..at + part.len()), at + part.len() <= 64) {
            dst.copy_from_slice(part);
            at += part.len();
        }
    }
    line(message.get(..at).unwrap_or(&[]));
}

fn fail(reason: &[u8]) -> ! {
    let mut message = [0u8; 96];
    let mut at = 0;
    for part in [b"fail: ".as_slice(), reason, b"\n".as_slice()] {
        if let (Some(dst), true) = (message.get_mut(at..at + part.len()), at + part.len() <= 96) {
            dst.copy_from_slice(part);
            at += part.len();
        }
    }
    line(message.get(..at).unwrap_or(&[]));
    exit(1)
}

/// `<prefix><demo key>\n` as one line; the key is 129 bytes so it needs the wide buffer.
fn line_key(prefix: &[u8]) {
    let mut out = [0u8; 320];
    let mut at = 0;
    for part in [WHO, prefix, KEY.as_bytes(), b"\n".as_slice()] {
        if let (Some(dst), true) = (out.get_mut(at..at + part.len()), at + part.len() <= 320) {
            dst.copy_from_slice(part);
            at += part.len();
        }
    }
    debug_write(out.get(..at).unwrap_or(&[]));
}

fn digits(mut value: u64) -> DecimalDigits {
    let mut out = DecimalDigits {
        bytes: [0; 20],
        start: 20,
    };
    loop {
        out.start -= 1;
        out.bytes[out.start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out
}

struct DecimalDigits {
    bytes: [u8; 20],
    start: usize,
}

impl DecimalDigits {
    fn as_slice(&self) -> &[u8] {
        self.bytes.get(self.start..).unwrap_or(&[])
    }
}
