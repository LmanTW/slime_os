#![no_std]
#![no_main]

//! The Zenoh service: one Zenoh session served to local holders by their grants.
//!
//! The grants come only from the authenticated `zenoh-service-grants-table` resource, read through the root. A holder
//! is the one whose control endpoint a request arrived on, so no request can name another holder. The service owns the
//! link to the peer through the network service, and the holders hold no network authority of their own. Each holder
//! gets a ring and a data page as shared-buffer loans, the way the network service provisions its applications, and
//! `slime_components::zenoh_service_server` answers each request.
//!
//! Nothing in this crate runs on the host. The server half, the core and the link are graded by their host tests, and
//! this crate is graded by the booted composition.

mod holders;

use slime_components::network_io::{
    Connection as ServiceConnection, NetworkIo, NetworkNotifications,
};
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_link::LinkOf;
use slime_components::zenoh_node::{self as node, Connection, Stream};
use slime_components::zenoh_profile0::session::{Config, Params, Role};
use slime_components::zenoh_service::Core;
use slime_components::zenoh_service::{OverLink, Row};
use slime_components::zenoh_service_server::Server;
use slime_proto::network_service as net;
use slime_proto::zenoh_service_grants_table::Table;
use slime_proto::zenoh_service_grants_table_wire as grants;
use slime_rt::console_line::Line;
use slime_rt::{
    exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now, zenoh_grants_read,
};

slime_rt::entry!(main);

/// The service's declared limits. `Core` is sized by them, so the generation's grants must hold exactly `ROWS` rows
/// for at most `HOLDERS` holders, and a table that does not is refused at start.
pub const HOLDERS: usize = 2;
pub const ROWS: usize = 2;
pub const SLOTS: usize = 4;
pub const PAYLOAD: usize = 12;
const PAGE_ROWS: usize = 6;
const TABLE_BYTES: usize = grants::HEADER_BYTES + ROWS * grants::ENTRY_BYTES;
const RING_BASE: u64 = 0x0000_001c_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const DEADLINE_MS: i64 = 20_000;
/// How many pumps the service gives the link to flush its CLOSE before it exits.
const CLOSE_PUMPS: usize = 64;

type Holders<'k> = Core<'k, HOLDERS, SLOTS, PAYLOAD, ROWS>;
pub type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, 514, 1, 5, 129, PAYLOAD, 8, 4>;

/// One connection of the network service, driven without blocking.
pub struct Wire<'a, 'b> {
    io: &'a mut NetworkIo<'b>,
    connection: &'a ServiceConnection,
}

impl Connection for Wire<'_, '_> {
    fn send(
        &mut self,
        bytes: &[u8],
    ) -> Result<node::Reply, slime_components::zenoh_link::LinkError> {
        self.io
            .send_nonblocking(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| slime_components::zenoh_link::LinkError::Reset)
    }

    fn recv(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<node::Reply, slime_components::zenoh_link::LinkError> {
        self.io
            .recv_nonblocking(self.connection, bytes)
            .map(|reply| reply_of(&reply))
            .map_err(|_| slime_components::zenoh_link::LinkError::Reset)
    }
}

fn reply_of(reply: &slime_components::network_io::NetworkReply) -> node::Reply {
    node::Reply {
        success: reply.is_success(),
        status: reply.status_detail,
        transferred: reply.transferred,
        end_of_stream: reply.flags == net::FLAG_END_OF_STREAM,
    }
}

fn main(_startup_arg: u32) {
    let mut object = [0u8; TABLE_BYTES];
    let len = read_grants(&mut object);
    let table = Table::decode(&object[..len]).unwrap_or_else(|_| fail(b"grants decode"));
    let mut names = [[0u8; grants::HOLDER_NAME_BYTES]; HOLDERS];
    let mut name_lens = [0usize; HOLDERS];
    let mut keys = [[0u8; grants::MAX_KEY_BYTES]; ROWS];
    let mut key_lens = [0usize; ROWS];
    let mut stored: [(usize, bool, bool); ROWS] = [(0, false, false); ROWS];
    let mut holder_count = 0;
    for index in 0..table.row_count() {
        let row = table.row(index).unwrap_or_else(|_| fail(b"grants row"));
        if index >= ROWS {
            fail(b"grants rows");
        }
        let at = (0..holder_count)
            .find(|at| &names[*at][..name_lens[*at]] == row.holder)
            .unwrap_or_else(|| {
                if holder_count == HOLDERS {
                    fail(b"grants holders");
                }
                names[holder_count][..row.holder.len()].copy_from_slice(row.holder);
                name_lens[holder_count] = row.holder.len();
                holder_count += 1;
                holder_count - 1
            });
        keys[index][..row.key.len()].copy_from_slice(row.key);
        key_lens[index] = row.key.len();
        stored[index] = (at, row.publish, row.subscribe);
    }
    let rows: [Row<'_>; ROWS] = core::array::from_fn(|index| Row {
        holder: stored[index].0,
        key: core::str::from_utf8(&keys[index][..key_lens[index]]).unwrap_or(""),
        publish: stored[index].1,
        subscribe: stored[index].2,
    });
    if table.row_count() != ROWS {
        fail(b"grants rows");
    }
    let live = &rows[..];
    Line::<128>::new()
        .bytes(b"[zenoh-service] grants rows=")
        .decimal(table.row_count() as u64)
        .bytes(b" holders=")
        .decimal(holder_count as u64)
        .bytes(b"\n")
        .emit();

    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    let params = Params {
        local: 3,
        per_side: 2,
        events: 4,
        ..Params::DEMO
    };
    let mut core = Holders::new(live, [0xe0; 16], &params).unwrap_or_else(|_| fail(b"grants core"));
    let mut over = OverLink::<PAYLOAD>::new();
    let mut server = Server::<HOLDERS>::new();

    let notifications = NetworkNotifications {
        request_signal: binding(b"notification:zenoh-network-request+signal"),
        completion_wait: binding(b"notification:zenoh-service-done+wait"),
        timeout_ticks: rate.checked_mul(5).unwrap_or_else(|| fail(b"timer range")),
    };
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the network service.
    let mut io = unsafe {
        NetworkIo::attach_with_notifications(
            binding(b"zenoh-service-control"),
            binding(b"zenoh-service-provision"),
            RING_BASE,
            DATA_BASE,
            notifications,
        )
    }
    .unwrap_or_else(|_| fail(b"network attach"));
    let connection = connect(&mut io, &clock);
    let wire = Wire {
        io: &mut io,
        connection: &connection,
    };
    let config = Config {
        zid: &[0xb2; 8],
        lease_ms: node::LEASE_MS,
        initial_sn: 0,
        cookie: &[0xc0; 32],
    };
    let mut link: Link<'_, '_> =
        LinkOf::with_params(Stream::new(wire), Role::Connector, &config, params, 1)
            .unwrap_or_else(|_| fail(b"session config"));
    let handle = link.handle();
    link.open(handle, 0).unwrap_or_else(|_| fail(b"link open"));
    let names = holders::Names {
        bytes: names,
        lens: name_lens,
        count: holder_count,
    };
    holders::serve(
        &mut core,
        &mut over,
        &mut server,
        &mut link,
        handle,
        &clock,
        &names,
    );
    // The CLOSE the link queues is flushed by later pumps, and the peer ends its session on receiving it.
    if link.close(handle, 0).is_ok() {
        for _ in 0..CLOSE_PUMPS {
            let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
            let _ = link.pump(handle, now as u64);
            if !link.send_pending() {
                break;
            }
            yield_now();
        }
    }
    drop(link);
    if !io
        .close(connection)
        .unwrap_or_else(|_| fail(b"close request"))
        .is_success()
    {
        fail(b"close");
    }
    io.finish().unwrap_or_else(|_| fail(b"finish"));
    exit(0)
}

fn connect(io: &mut NetworkIo<'_>, clock: &TickClock) -> ServiceConnection {
    let start = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    loop {
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
        let now = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
        if clock.millis(now) - clock.millis(start) >= DEADLINE_MS {
            fail(b"deadline");
        }
        yield_now();
    }
}

fn read_grants(object: &mut [u8; TABLE_BYTES]) -> usize {
    let mut rows = 0usize;
    loop {
        let mut page = [0u8; PAGE_ROWS * grants::ENTRY_BYTES];
        let read = zenoh_grants_read(rows, &mut page).unwrap_or_else(|_| fail(b"grants read"));
        if read == 0 {
            break;
        }
        if read > PAGE_ROWS || rows + read > ROWS {
            fail(b"grants page");
        }
        let bytes = read * grants::ENTRY_BYTES;
        let start = grants::HEADER_BYTES + rows * grants::ENTRY_BYTES;
        object[start..start + bytes].copy_from_slice(&page[..bytes]);
        rows += read;
    }
    let header = grants::WireGrantsHeader {
        magic: grants::TABLE_MAGIC,
        format_version: grants::FORMAT_VERSION,
        header_size: grants::HEADER_BYTES as u32,
        required_flags: 0,
        row_count: rows as u32,
        total_len: (grants::HEADER_BYTES + rows * grants::ENTRY_BYTES) as u32,
    };
    object[..grants::HEADER_BYTES].copy_from_slice(&header.encode());
    grants::HEADER_BYTES + rows * grants::ENTRY_BYTES
}

pub fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
}

pub fn fail(reason: &[u8]) -> ! {
    Line::<128>::new()
        .bytes(b"[zenoh-service] fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}
