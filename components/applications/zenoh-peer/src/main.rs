#![no_std]
#![no_main]

//! The peer of the Zenoh service composition: a Zenoh Profile 0 listener that accepts the service's connection and
//! completes the session. It declares no subscriber, so a publication the service sends is not delivered here, and it
//! ends when the service closes the session.

use slime_components::network_io::{
    Connection as ServiceConnection, NetworkError, NetworkIo, NetworkNotifications, NetworkReply,
};
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::{Link, LinkError, Notice};
use slime_components::zenoh_node::{self as node, Connection, Reply, Stream};
use slime_components::zenoh_profile0::session::{Config, Role};
use slime_proto::network_service as net;
use slime_rt::console_line::Line;
use slime_rt::{exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"zenoh-peer";
const RING_BASE: u64 = 0x0000_001c_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const DEADLINE_MS: i64 = 30_000;
const ZID: [u8; 8] = [0xd4; 8];

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

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:zenoh-network-request+signal"),
        completion_wait: binding(b"notification:zenoh-peer-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the network service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-peer-control"),
            binding(b"zenoh-peer-provision"),
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
            cookie: node::COOKIE,
        };
        let mut link = Link::new(Stream::new(wire), Role::Listener, &config, 1)
            .unwrap_or_else(|_| fail(b"session config"));
        let handle = link.handle();
        loop {
            let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
            link.pump(handle, now as u64)
                .unwrap_or_else(|_| fail(b"link"));
            let mut ended = false;
            while let Some(notice) = link.next_notice() {
                match notice {
                    Notice::HandshakeComplete => {
                        Line::<96>::new()
                            .bytes(b"[zenoh-peer] session open\n")
                            .emit();
                    }
                    Notice::Closed { .. } => ended = true,
                    // The service declares the subscription of its holder, and may undeclare it.
                    Notice::SubscriberDeclared { .. } | Notice::SubscriberUndeclared { .. } => {}
                    // The peer declares nothing, so no sample is addressed to it.
                    Notice::SampleDelivered(_) | Notice::SampleStored(_) => {
                        fail(b"unexpected sample")
                    }
                }
            }
            if ended {
                break;
            }
            idle(&clock);
        }
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
        .bytes(b"[zenoh-peer] session closed\n")
        .emit();
    exit(0)
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
