#![no_std]
#![no_main]

//! The rmw_zenoh node: a Zenoh Profile 0 graph listener that exchanges one topic with an rmw_zenoh peer.
//!
//! The node accepts one connection of the network service and runs a graph link over it. It declares its one
//! subscription on the chat key, writes a Put on that key for each string it publishes once the peer has
//! subscribed, and prints every sample the peer sent. It owns its link and has no holder, so it holds the
//! network service's authority and nothing else.
//!
//! Nothing in this crate runs on the host. The link and its queue are graded by `zenoh_rmw_data_link_check`, and
//! this crate is graded by the booted composition that runs it.

use slime_components::network_io::{
    Connection as ServiceConnection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::LinkError;
use slime_components::zenoh_node::{self as node, Connection, Reply, Stream};
use slime_components::zenoh_profile0::encode;
use slime_components::zenoh_profile0::session::{Config, Params, Role};
use slime_components::zenoh_rmw_link::{GraphLinkError, GraphLinkOf};
use slime_proto::network_service as net;
use slime_rt::console_line::Line;
use slime_rt::{exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"zenoh-rmw-node";
const RING_BASE: u64 = 0x0000_001c_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const DEADLINE_MS: i64 = 30_000;
const ZID: [u8; 16] = [
    0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
];
const COOKIE: &[u8] = b"slime-rmw-node-cookie-01";
/// The sizes the link was judged at by `zenoh_rmw_data_link_check`.
const FRAMED: usize = 512;
const SLOTS: usize = 32;
const KEY: usize = 253;
const ENTITIES: usize = 16;
const QUEUE: usize = 16;
const SLOT_BYTES: usize = 32;
const DOMAIN: u64 = 0;
const SUBSCRIPTION_ID: u32 = 1;
/// The topic: `std_msgs/String` on `chatter`, as an rmw_zenoh peer names it.
const CHAT_KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
/// How many strings the node publishes.
const PUBLISHED: usize = 4;
/// How many pumps the node gives the link to flush its CLOSE before it exits.
const CLOSE_PUMPS: usize = 64;

type Link<'a, 'b> =
    GraphLinkOf<Stream<Wire<'a, 'b>>, FRAMED, SLOTS, SLOTS, KEY, ENTITIES, QUEUE, SLOT_BYTES>;

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

/// A `std_msgs/String` in classic CDR: the encapsulation header, a 4-byte length and the NUL-ended text.
fn cdr_string(text: &[u8], out: &mut [u8]) -> usize {
    let length = text.len() + 1;
    out[..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    out[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    out[8..8 + text.len()].copy_from_slice(text);
    out[8 + text.len()] = 0;
    8 + length
}

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:zenoh-network-request+signal"),
        completion_wait: binding(b"notification:zenoh-rmw-node-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the network service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-rmw-node-control"),
            binding(b"zenoh-rmw-node-provision"),
            RING_BASE,
            DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|error| fail(attach_reason(error)));

    let listener = io
        .listen_ipv4(node::ENDPOINT, node::PORT)
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
        idle(&clock);
    };
    {
        let wire = Wire {
            io: &mut io,
            connection: &connection,
        };
        let config = Config {
            zid: &ZID,
            lease_ms: node::LEASE_MS,
            initial_sn: 0,
            cookie: COOKIE,
        };
        let mut link = Link::new(
            Stream::new(wire),
            Role::Listener,
            &config,
            Params::GRAPH,
            DOMAIN,
            1,
        )
        .unwrap_or_else(|_| fail(b"session config"));
        run(&mut link, &clock);
    }
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
    Line::<96>::new()
        .bytes(b"[zenoh-rmw-node] session closed\n")
        .emit();
    exit(0)
}

/// Drives the link: declares the subscription once the session is open, publishes after the peer subscribes, and
/// prints each sample. It returns when the link ends, which is the peer's CLOSE or a refusal. A peer that never
/// closes ends the node at the deadline as a failure, with no CLOSE written.
fn run(link: &mut Link<'_, '_>, clock: &TickClock) {
    let handle = link.handle();
    let mut declared = false;
    let mut published = 0usize;
    loop {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
        link.pump(handle, now as u64)
            .unwrap_or_else(|_| fail(b"link"));
        if link.is_closed() {
            break;
        }
        if link.is_open() && !declared && !link.send_pending() {
            link.declare_subscriber(handle, SUBSCRIPTION_ID, CHAT_KEY)
                .unwrap_or_else(|_| fail(b"declare subscriber"));
            declared = true;
            Line::<96>::new()
                .bytes(b"[zenoh-rmw-node] subscription declared\n")
                .emit();
        }
        while let Some(sample) = link.pop_sample() {
            Line::<128>::new()
                .bytes(b"[zenoh-rmw-node] received sequence=")
                .decimal(sample.sequence as u64)
                .bytes(b"\n")
                .emit();
        }
        if declared && published < PUBLISHED && !link.send_pending() {
            let mut text = [0u8; 24];
            let used = line_text(published, &mut text);
            let mut payload = [0u8; SLOT_BYTES];
            let length = cdr_string(&text[..used], &mut payload);
            let attachment = encode::attachment(published as i64 + 1, now, &node::GID)
                .unwrap_or_else(|_| fail(b"attachment"));
            match link.send_put(handle, CHAT_KEY, &attachment, &payload[..length]) {
                Ok(()) => {
                    published += 1;
                    Line::<96>::new()
                        .bytes(b"[zenoh-rmw-node] published sequence=")
                        .decimal(published as u64)
                        .bytes(b"\n")
                        .emit();
                }
                // The peer has not subscribed yet, so a Put has no key to go to. It is tried again.
                Err(GraphLinkError::Graph(_)) | Err(GraphLinkError::SendBusy) => {}
                Err(_) => fail(b"put"),
            }
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

/// `Hello Slime <n>`, without a formatter.
fn line_text(number: usize, out: &mut [u8; 24]) -> usize {
    let prefix = b"Hello Slime ";
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()] = b'0' + (number % 10) as u8;
    prefix.len() + 1
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
