#![no_std]
#![no_main]

//! The rmw_zenoh native peer: a plain Zenoh Profile 0 connector that dials the rmw_zenoh node and exchanges one topic
//! with it.
//!
//! The peer opens a session, declares its one subscription on the chatter key, and waits for the node to declare
//! its own. It then writes a Put on that key for each string it publishes and prints every sample the node sent.
//! The node runs a graph link and the peer runs the plain link, with a key and a payload bound that fit the chatter
//! key and a `std_msgs/String`.
//!
//! Nothing in this crate runs on the host. The plain link is graded by `zenoh_links_check`, and this crate is graded
//! by the booted composition that runs it.

use slime_components::network_io::{
    Connection as ServiceConnection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::{LinkError, LinkOf, Notice};
use slime_components::zenoh_node::{self as node, Connection, Reply, Stream};
use slime_components::zenoh_profile0::encode;
use slime_components::zenoh_profile0::session::{Config, Params, Role};
use slime_components::zenoh_profile0::{Bounds, STREAM_LENGTH_BYTES};
use slime_proto::network_service as net;
use slime_rt::console_line::Line;
use slime_rt::{exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"zenoh-rmw-peer";
const RING_BASE: u64 = 0x0000_001c_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const DEADLINE_MS: i64 = 30_000;
const ZID: [u8; 8] = [0xa1; 8];
/// The sizes the plain link was configured at for the chatter key and a `std_msgs/String`: the 110-byte key
/// fits 253 and the longest string, 22 bytes as classic CDR, fits 32.
const FRAMED: usize = 512;
const KEY: usize = 253;
const PAYLOAD: usize = 32;
const NOTICES: usize = 8;
const SUBSCRIPTION_ID: u32 = 1;
/// The topic: `std_msgs/String` on `chatter`, as an rmw_zenoh peer names it.
const CHAT_KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
/// How many strings the peer publishes.
const PUBLISHED: usize = 4;
/// How many connection attempts the peer makes before it fails, one for each time the node is not yet listening.
const CONNECT_ATTEMPTS: u32 = 64;
/// How many pumps the peer gives the link to flush its CLOSE before it exits.
const CLOSE_PUMPS: usize = 64;

type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, FRAMED, 1, 2, KEY, PAYLOAD, NOTICES>;

/// One connection of the network service, driven without blocking.
struct Wire<'a, 'b> {
    io: &'a mut NetworkIo<'b>,
    connection: &'a ServiceConnection,
}

fn reply_of(reply: &NetworkReply) -> Reply {
    Reply {
        success: reply.is_success(),
        status: reply.status_detail,
        transferred: reply.transferred,
        end_of_stream: reply.flags == net::FLAG_END_OF_STREAM,
    }
}

impl Connection for Wire<'_, '_> {
    fn send(&mut self, bytes: &[u8]) -> Result<Reply, LinkError> {
        self.io
            .send_nonblocking(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| LinkError::Reset)
    }

    fn recv(&mut self, bytes: &mut [u8]) -> Result<Reply, LinkError> {
        self.io
            .recv_nonblocking(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| LinkError::Reset)
    }
}

/// The plain link's parameters for the chatter key: the demo's, with a 253-byte key and a 32-byte payload.
fn params() -> Params {
    let mut params = Params::DEMO;
    params.bounds = Bounds {
        batch: FRAMED - STREAM_LENGTH_BYTES,
        key: KEY,
        payload: PAYLOAD,
    };
    params.announced = FRAMED as u16;
    params.samples = NOTICES / 2;
    params
}

/// A `std_msgs/String` in classic CDR: the encapsulation header, a 4-byte length and the NUL-ended text.
fn cdr_string(text: &[u8], out: &mut [u8]) -> usize {
    let length = text.len() + 1;
    out[..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    out[8..8 + text.len()].copy_from_slice(text);
    out[8 + text.len()] = 0;
    8 + length
}

/// `Hello Peer <n>`, without a formatter. The node's strings are `Hello Slime <n>`, so a sample names its sender.
fn line_text(number: usize, out: &mut [u8; 24]) -> usize {
    let prefix = b"Hello Peer ";
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()] = b'0' + (number % 10) as u8;
    prefix.len() + 1
}

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:zenoh-network-request+signal"),
        completion_wait: binding(b"notification:zenoh-rmw-peer-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the network service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-rmw-peer-control"),
            binding(b"zenoh-rmw-peer-provision"),
            RING_BASE,
            DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|error| fail(attach_reason(error)));

    let connection = connect(&mut io, &clock);
    {
        let wire = Wire {
            io: &mut io,
            connection: &connection,
        };
        let config = Config {
            zid: &ZID,
            lease_ms: node::LEASE_MS,
            initial_sn: 0,
            cookie: b"",
        };
        let mut link = Link::with_params(Stream::new(wire), Role::Connector, &config, params(), 1)
            .unwrap_or_else(|_| fail(b"session config"));
        run(&mut link, &clock);
    }
    if !io
        .close(connection)
        .unwrap_or_else(|_| fail(b"close request"))
        .is_success()
    {
        fail(b"close");
    }
    io.finish().unwrap_or_else(|_| fail(b"finish"));
    Line::<96>::new()
        .bytes(b"[zenoh-rmw-peer] session closed\n")
        .emit();
    exit(0)
}

/// Dials the node, trying again while it is not yet listening.
fn connect(io: &mut NetworkIo<'_>, clock: &TickClock) -> ServiceConnection {
    for _ in 0..CONNECT_ATTEMPTS {
        let mut reply = io
            .connect_ipv4(node::ENDPOINT, node::PORT)
            .unwrap_or_else(|_| fail(b"connect request"));
        if let Some(connection) = reply.take_connection() {
            return connection;
        }
        if !matches!(
            reply.status_detail,
            net::STATUS_REFUSED | net::STATUS_WOULD_BLOCK
        ) {
            fail(b"connect refused");
        }
        idle(clock);
    }
    fail(b"connect attempts")
}

/// Drives the link: opens the session, declares the subscription, publishes once the node has subscribed, and prints
/// each sample. It returns when the link ends, which is the node's CLOSE or a refusal. A node that never closes ends
/// the peer at the deadline as a failure, with no CLOSE written.
fn run(link: &mut Link<'_, '_>, clock: &TickClock) {
    let handle = link.handle();
    let mut opened = false;
    let mut subscribed = false;
    let mut declared = false;
    let mut published = 0usize;
    loop {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
        if !opened {
            link.open(handle, now as u64)
                .unwrap_or_else(|_| fail(b"open"));
            opened = true;
        }
        link.pump(handle, now as u64)
            .unwrap_or_else(|_| fail(b"link"));
        if link.is_closed() {
            break;
        }
        while let Some(notice) = link.next_notice() {
            match notice {
                Notice::HandshakeComplete => {
                    Line::<96>::new()
                        .bytes(b"[zenoh-rmw-peer] session open\n")
                        .emit();
                }
                Notice::SubscriberDeclared { .. } => subscribed = true,
                Notice::SampleDelivered(sample) => {
                    Line::<128>::new()
                        .bytes(b"[zenoh-rmw-peer] received sequence=")
                        .decimal(sample.sequence as u64)
                        .bytes(b"\n")
                        .emit();
                }
                Notice::Closed { .. } => {}
                _ => {}
            }
        }
        if link.is_open() && !declared && !link.send_pending() {
            link.declare_subscriber(handle, SUBSCRIPTION_ID, CHAT_KEY)
                .unwrap_or_else(|_| fail(b"declare subscriber"));
            declared = true;
            Line::<96>::new()
                .bytes(b"[zenoh-rmw-peer] subscription declared\n")
                .emit();
        }
        if subscribed && published < PUBLISHED && !link.send_pending() {
            let mut text = [0u8; 24];
            let used = line_text(published, &mut text);
            let mut payload = [0u8; PAYLOAD];
            let length = cdr_string(&text[..used], &mut payload);
            let attachment = encode::attachment(published as i64 + 1, now, &node::GID)
                .unwrap_or_else(|_| fail(b"attachment"));
            link.publish(handle, CHAT_KEY, &attachment, &payload[..length])
                .unwrap_or_else(|_| fail(b"publish"));
            published += 1;
            Line::<96>::new()
                .bytes(b"[zenoh-rmw-peer] published sequence=")
                .decimal(published as u64)
                .bytes(b"\n")
                .emit();
        }
        idle(clock);
    }
    for _ in 0..CLOSE_PUMPS {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
        let _ = link.pump(handle, now as u64);
        if !link.send_pending() {
            break;
        }
        yield_now();
    }
}

fn idle(clock: &TickClock) {
    let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
    if now >= DEADLINE_MS {
        fail(b"deadline");
    }
    yield_now();
}

fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
}

fn attach_reason(error: NetworkError) -> &'static [u8] {
    match error {
        NetworkError::Setup => b"attach: setup",
        NetworkError::BadRequest => b"attach: bad request",
        NetworkError::Malformed => b"attach: malformed",
        NetworkError::Lost => b"attach: lost",
    }
}

fn fail(reason: &[u8]) -> ! {
    Line::<128>::new()
        .bytes(b"[")
        .bytes(NAME)
        .bytes(b"] fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}
