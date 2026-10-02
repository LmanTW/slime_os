#![no_std]
#![no_main]

//! The demo's publisher node: a Zenoh Profile 0 connector that publishes the four
//! declared `Counter` samples once the subscriber has declared the demo key.

use slime_components::network_io::{
    Connection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::ros_cdr::Counter;
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::{ByteLink, Link, LinkError, Notice};
use slime_components::zenoh_profile0::encode;
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
const SAMPLES: [(u32, i32); 4] = [(0, 10), (1, 20), (2, 30), (3, 40)];
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
const ZID: [u8; 8] = [0xa1; 8];
const LEASE_MS: u64 = 2000;
const LINE_BYTES: usize = 128;
const WHO: &[u8] = b"[ros2-demo-publisher] ";

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
        completion_wait: binding(b"notification:zenoh-publisher-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this
    // adapter, and the two declared endpoints belong to the same service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-publisher-control"),
            binding(b"zenoh-publisher-provision"),
            RING_BASE,
            DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|_| fail(b"attach"));

    denials(&mut io);
    let connection = connect(&mut io, &clock);
    let config = Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: 0,
        cookie: b"",
    };
    let link = Link::new(
        Stream {
            io: &mut io,
            connection: &connection,
            eof: false,
        },
        Role::Connector,
        &config,
        1,
    )
    .unwrap_or_else(|_| fail(b"session config"));
    let published = run(link, &clock);
    if published != SAMPLES.len() {
        fail(b"samples published");
    }
    if !io
        .close(connection)
        .unwrap_or_else(|_| fail(b"close request"))
        .is_success()
    {
        fail(b"close");
    }
    io.finish().unwrap_or_else(|_| fail(b"finish"));
    line(b"session closed samples=4\n");
    marker_denial(b"scouting");
    exit(0)
}

/// Requests the generation did not grant, each of which must be denied by name.
fn denials(io: &mut NetworkIo<'_>) {
    refused(io.connect_ipv4([127, 0, 0, 2], PORT));
    refused(io.connect_ipv4(ADDRESS, PORT + 1));
    marker_denial(b"undeclared-endpoint");
    refused(io.listen_ipv4(ADDRESS, PORT));
    marker_denial(b"listen");
}

fn refused(reply: Result<NetworkReply, NetworkError>) {
    let reply = reply.unwrap_or_else(|_| fail(b"authority request transport"));
    if reply.status_detail != net::STATUS_DENIED
        || reply.transferred != 0
        || reply.capability_kind != net::CAPABILITY_NONE
        || reply.capability != 0
    {
        fail(b"authority refusal result");
    }
}

fn connect(io: &mut NetworkIo<'_>, clock: &TickClock) -> Connection {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let mut reply = io
            .connect_ipv4(ADDRESS, PORT)
            .unwrap_or_else(|_| fail(b"connect request"));
        if let Some(connection) = reply.take_connection() {
            return connection;
        }
        if !matches!(
            reply.status_detail,
            net::STATUS_REFUSED | net::STATUS_WOULD_BLOCK
        ) || attempts >= 64
        {
            fail(b"connect refused");
        }
        bounded_yield(clock);
    }
}

fn run(mut link: Link<Stream<'_, '_>>, clock: &TickClock) -> usize {
    let handle = link.handle();
    link.open(handle, 0).unwrap_or_else(|_| fail(b"open"));
    let mut next = 0;
    let mut declared = false;
    let mut announced = false;
    loop {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read"))) as u64;
        if link.pump(handle, now).is_err() {
            fail(b"link");
        }
        while let Some(notice) = link.next_notice() {
            match notice {
                Notice::HandshakeComplete if !announced => {
                    announced = true;
                    line(b"session open role=connector initial_sn=0 lease_ms=2000\n");
                }
                Notice::SubscriberDeclared { .. } if !declared => {
                    declared = true;
                    line_key(b"declaration matched key=");
                }
                Notice::Closed { .. } => {
                    if next == SAMPLES.len() {
                        return next;
                    }
                    fail(b"peer closed early");
                }
                _ => {}
            }
        }
        if declared && next < SAMPLES.len() && !link.send_pending() {
            let (sequence, value) = SAMPLES[next];
            publish(&mut link, handle, next, sequence, value);
            next += 1;
        }
        if next == SAMPLES.len() && !link.send_pending() && link.is_closed() {
            return next;
        }
        bounded_yield(clock);
    }
}

fn publish(
    link: &mut Link<Stream<'_, '_>>,
    handle: slime_components::zenoh_link::LinkHandle,
    index: usize,
    sequence: u32,
    value: i32,
) {
    let mut cdr = [0u8; slime_components::ros_cdr::MAX_SERIALIZED_BYTES];
    let counter = Counter { sequence, value };
    let length = counter
        .encode(&mut cdr)
        .unwrap_or_else(|_| fail(b"cdr encode"));
    let attachment = encode::attachment(i64::from(sequence) + 1, 1000 + i64::from(sequence), &GID)
        .unwrap_or_else(|_| fail(b"attachment"));
    let payload = cdr.get(..length).unwrap_or(&[]);
    link.publish(handle, KEY, &attachment, payload)
        .unwrap_or_else(|_| fail(b"publish"));
    write_wire_line(b"wire sent", index, link.last_sent_batch());
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
