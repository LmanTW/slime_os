//! The server exam: the server driven with the client protocol's bytes, printing one `[zenoh-exam] server ...` line
//! for each answer. `scripts/check/check-zenoh-profile0.py --slice server` owns what those lines must be, and
//! `scripts/lib/zenoh_server_exam.py` owns every byte of them, written from the schema's layout.
//!
//! The setup is two holders and four rows, in the grant order the holders see them. Holder 0 has row 0, which
//! publishes the first key, and row 1, which publishes and subscribes the second key. Holder 1 has row 0, which
//! subscribes the first key, and row 1, which subscribes the second. Holder 2 has no row. A ring holds two samples
//! of up to twelve bytes. The service's clock starts at 100 and advances by one for each publication. The peer
//! declares the second key after the second publication.

use super::{Answer, HEADER_BYTES, Server};
use crate::zenoh_link::LinkHandle;
use crate::zenoh_profile0::session::Params;
use crate::zenoh_service::{Core, OverLink, Row};
use crate::zenoh_service_link::pair::{Far, Svc, pair};
use slime_proto::zenoh_service_client as wire;
use slime_proto::zenoh_service_client_wire::WireServiceRequest;
use std::string::String;

type Holders = Core<'static, 3, 2, 12, 4>;

const KEYS: [&str; 2] = ["0/slime_demo/server/first", "0/slime_demo/server/second"];
const GID: [u8; 16] = [0xe0; 16];
const START: i64 = 100;
const PAGE: usize = 4096;

fn rows() -> [Row<'static>; 4] {
    [
        Row {
            holder: 0,
            key: KEYS[0],
            publish: true,
            subscribe: false,
        },
        Row {
            holder: 0,
            key: KEYS[1],
            publish: true,
            subscribe: true,
        },
        Row {
            holder: 1,
            key: KEYS[0],
            publish: false,
            subscribe: true,
        },
        Row {
            holder: 1,
            key: KEYS[1],
            publish: false,
            subscribe: true,
        },
    ]
}

fn params() -> Params {
    crate::zenoh_service::exam::params()
}

fn line(text: &str) {
    println!("[zenoh-exam] server {text}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

struct World {
    server: Server<3>,
    core: Holders,
    over: OverLink<'static, 12>,
    link: Svc,
    peer: Far,
    handle: LinkHandle,
    peer_handle: LinkHandle,
    clock: i64,
    tick: u64,
}

impl World {
    fn new() -> Self {
        let (link, peer, handle, peer_handle) = pair();
        let core = Holders::new(&rows(), GID, &params()).expect("the grants");
        Self {
            server: Server::new(),
            core,
            over: OverLink::new(),
            link,
            peer,
            handle,
            peer_handle,
            clock: START,
            tick: 100,
        }
    }

    fn control(&mut self, holder: usize, bytes: &[u8]) -> Answer {
        self.server.control(&self.core, holder, bytes)
    }

    fn ask(&mut self, holder: usize, bytes: &[u8], payload: &[u8], page: &mut [u8]) -> Answer {
        self.tick += 1;
        self.server.request(
            &mut self.core,
            &mut self.over,
            &mut self.link,
            self.handle,
            holder,
            bytes,
            payload,
            page,
            self.clock,
            self.tick,
        )
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
    }
}

fn done(answer: &Answer) -> String {
    hex(&answer.completion)
}

/// A request the exam sends, its completion, and the words in front of them.
fn say(words: &str, sent: &[u8], answer: &Answer) {
    line(&format!(
        "{words} request {} completion {}",
        hex(sent),
        done(answer)
    ));
}

fn take(world: &mut World, holder: usize, label: &str, buffer: usize) -> Answer {
    let sent = request(wire::OP_TAKE, 0, 0);
    let mut page = vec![0u8; buffer];
    let answer = world.ask(holder, &sent, &[], &mut page);
    let item = answer.completion[7];
    let status = i32::from_le_bytes(answer.completion[8..12].try_into().expect("four bytes"));
    let row = u16::from_le_bytes(answer.completion[12..14].try_into().expect("two bytes"));
    let length = u32::from_le_bytes(answer.completion[16..20].try_into().expect("four bytes"));
    if status != 0 {
        say(
            &format!("{label} {holder} refused too-large"),
            &sent,
            &answer,
        );
    } else if i64::from(item) == wire::ITEM_SAMPLE {
        let sequence = i64::from_le_bytes(page[0..8].try_into().expect("eight bytes"));
        let timestamp = i64::from_le_bytes(page[8..16].try_into().expect("eight bytes"));
        let end = HEADER_BYTES + length as usize;
        say(
            &format!(
                "{label} {holder} sample row {row} sequence {sequence} timestamp {timestamp} page {}",
                hex(&page[..end])
            ),
            &sent,
            &answer,
        );
    } else if i64::from(item) == wire::ITEM_LOSS {
        say(&format!("{label} {holder} loss {length}"), &sent, &answer);
    } else {
        say(&format!("{label} {holder} none"), &sent, &answer);
    }
    answer
}

fn publish(world: &mut World, holder: usize, row: u16, sequence: i64, payload: &[u8]) -> Answer {
    let sent = request(wire::OP_PUBLISH, row, sequence);
    let mut page = [0u8; PAGE];
    let answer = world.ask(holder, &sent, payload, &mut page);
    let flags = u32::from_le_bytes(answer.completion[20..24].try_into().expect("four bytes"));
    let reached = u32::from_le_bytes(answer.completion[16..20].try_into().expect("four bytes"));
    let peer = if flags & wire::FLAG_PEER_SENT as u32 != 0 {
        "sent"
    } else {
        "none"
    };
    world.clock += 1;
    say(
        &format!(
            "publish {holder} row {row} sequence {sequence} length {} reached {reached} peer {peer}",
            payload.len()
        ),
        &sent,
        &answer,
    );
    answer
}

fn refused_publish(world: &mut World, name: &str, holder: usize, sent: [u8; 32], payload: &[u8]) {
    let mut page = [0u8; PAGE];
    let answer = world.ask(holder, &sent, payload, &mut page);
    let status = i32::from_le_bytes(answer.completion[8..12].try_into().expect("four bytes"));
    let class = match i64::from(status) {
        wire::STATUS_DENIED => "denied",
        wire::STATUS_MALFORMED => "malformed",
        wire::STATUS_TOO_LARGE => "too-large",
        wire::STATUS_LINK_CLOSED => "link-closed",
        other => panic!("a status the exam does not name: {other}"),
    };
    say(&format!("{name} {holder} refused {class}"), &sent, &answer);
}

pub fn run() {
    let mut world = World::new();

    // Attach. A holder with rows gets its row count. A holder with none, and a holder already attached, is denied.
    for holder in [0usize, 1] {
        let sent = request(wire::OP_ATTACH, 0, 0);
        let answer = world.control(holder, &sent);
        say(&format!("attach {holder} rows 2"), &sent, &answer);
    }
    let sent = request(wire::OP_ATTACH, 0, 0);
    let answer = world.control(2, &sent);
    say("attach 2 refused denied", &sent, &answer);
    let answer = world.control(0, &sent);
    say("attach-again 0 refused denied", &sent, &answer);

    // A publication on the first key reaches the one holder that subscribes to it. The service stamps the time.
    publish(&mut world, 0, 0, 5, &[1, 2, 3]);
    take(&mut world, 1, "take", PAGE);
    take(&mut world, 1, "take", PAGE);

    // A publication on the second key reaches its publisher too.
    publish(&mut world, 0, 1, 6, &[9, 8]);
    take(&mut world, 0, "take", PAGE);
    take(&mut world, 1, "take", PAGE);

    // The peer declares the second key, and the next publication is sent to it.
    world.peer_declares(1, KEYS[1]);
    publish(&mut world, 0, 1, 7, &[4]);
    take(&mut world, 0, "take", PAGE);
    take(&mut world, 1, "take", PAGE);

    // A refused publication reaches no ring and sends nothing.
    refused_publish(
        &mut world,
        "publish",
        1,
        request(wire::OP_PUBLISH, 0, 8),
        &[],
    );
    refused_publish(
        &mut world,
        "publish",
        0,
        request(wire::OP_PUBLISH, 9, 8),
        &[],
    );
    refused_publish(
        &mut world,
        "publish",
        2,
        request(wire::OP_PUBLISH, 0, 8),
        &[],
    );
    refused_publish(
        &mut world,
        "publish-too-large",
        0,
        request(wire::OP_PUBLISH, 0, 8),
        &[0u8; 13],
    );
    take(&mut world, 1, "take", PAGE);

    // A full ring drops its oldest sample and says so once, before the samples that remain.
    for sequence in [10, 11, 12] {
        publish(&mut world, 0, 0, sequence, &[sequence as u8]);
    }
    take(&mut world, 1, "take", PAGE);
    take(&mut world, 1, "take", PAGE);
    take(&mut world, 1, "take", PAGE);

    // A take whose buffer is smaller than the next sample is refused, and the sample stays in the ring.
    publish(&mut world, 0, 0, 13, &[1, 1, 1, 1]);
    take(&mut world, 1, "take-small-buffer", HEADER_BYTES + 3);
    take(&mut world, 1, "take", PAGE);

    // A request outside the protocol is answered with the operation it names, and changes nothing.
    for (name, mutate) in [
        ("wrong-magic", 0usize),
        ("wrong-version", 1),
        ("nonzero-reserved", 2),
        ("nonzero-flags", 3),
        ("unsupported-operation", 4),
    ] {
        let mut good = request(wire::OP_PUBLISH, 0, 1);
        match mutate {
            0 => good[0..4].copy_from_slice(&[0; 4]),
            1 => good[4..6].copy_from_slice(&2u16.to_le_bytes()),
            2 => good[10] = 1,
            3 => good[7] = 1,
            _ => good[6] = 9,
        }
        let mut page = [0u8; PAGE];
        let answer = world.ask(0, &good, &[], &mut page);
        line(&format!(
            "malformed {name} request {} completion {}",
            hex(&good),
            done(&answer)
        ));
    }

    // A publication while the link is closed is answered as such, and the local copies are not delivered.
    world
        .link
        .close(world.handle, 0)
        .expect("the service closes the link");
    refused_publish(
        &mut world,
        "publish-link-closed",
        0,
        request(wire::OP_PUBLISH, 1, 14),
        &[],
    );
    take(&mut world, 1, "take", PAGE);

    // Teardown. A holder that detached has no session, and neither has a holder that aborted.
    for (holder, op, name) in [
        (1usize, wire::OP_DETACH, "detach"),
        (0, wire::OP_ABORT, "abort"),
    ] {
        let sent = request(op, 0, 0);
        let answer = world.control(holder, &sent);
        say(&format!("{name} {holder} ok"), &sent, &answer);
    }
    let mut page = [0u8; PAGE];
    let sent = request(wire::OP_TAKE, 0, 0);
    let answer = world.ask(1, &sent, &[], &mut page);
    say("take-after-detach 1 refused denied", &sent, &answer);
    refused_publish(
        &mut world,
        "publish-after-abort",
        0,
        request(wire::OP_PUBLISH, 0, 15),
        &[],
    );
    line("ok every-request-is-answered-and-no-grant-is-widened");
}
