#![no_std]
#![no_main]

//! A holder of the Zenoh service that publishes four samples on the key its grant allows, then detaches.
//!
//! The holder owns no network authority. It reaches the service through the two endpoints the composition grants it,
//! and the service learns which holder it is from the endpoint a request arrives on.

use slime_components::tick_clock::TickClock;
use slime_components::zenoh_service_client::ClientIo;
use slime_proto::zenoh_service_client as wire;
use slime_rt::console_line::Line;
use slime_rt::{exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"alpha";
const RING_BASE: u64 = 0x0000_001e_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const SAMPLES: i64 = 4;
const PAYLOAD_BYTES: usize = 12;
/// How long a publication may be refused because the service's link is not open yet.
const OPEN_DEADLINE_MS: i64 = 12_000;
/// How long the holder waits between publications, so the subscriber takes each sample before the next is published.
const SPACING_MS: i64 = 50;

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the Zenoh service.
    let mut io = unsafe {
        ClientIo::attach(
            binding(b"alpha-zenoh-control"),
            binding(b"alpha-zenoh-provision"),
            RING_BASE,
            DATA_BASE,
        )
    }
    .unwrap_or_else(|_| fail(b"attach"));
    if io.rows() != 1 {
        fail(b"rows");
    }
    for sequence in 0..SAMPLES {
        let payload = [sequence as u8; PAYLOAD_BYTES];
        // A refusal for a link that is not open sent nothing, so the same publication is offered again.
        let reply = loop {
            let reply = io
                .publish(0, sequence, &payload)
                .unwrap_or_else(|_| fail(b"publish"));
            if reply.status != wire::STATUS_LINK_CLOSED as i32 {
                break reply;
            }
            if clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")))
                >= OPEN_DEADLINE_MS
            {
                fail(b"link not open");
            }
            yield_now();
        };
        if reply.status != wire::STATUS_SUCCESS as i32 || reply.reached != 1 {
            fail(b"publication result");
        }
        wait(&clock, SPACING_MS);
    }
    io.finish().unwrap_or_else(|_| fail(b"detach"));
    exit(0)
}

fn wait(clock: &TickClock, milliseconds: i64) {
    let start = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
    loop {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
        if now - start >= milliseconds {
            return;
        }
        yield_now();
    }
}

fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
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
