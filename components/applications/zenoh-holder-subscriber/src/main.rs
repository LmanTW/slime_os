#![no_std]
#![no_main]

//! A holder of the Zenoh service that takes the four samples published on its subscription, then asks to publish on
//! a row it may only subscribe to and expects the service to refuse. It detaches last.

use slime_components::tick_clock::TickClock;
use slime_components::zenoh_service_client::{ClientIo, Item};
use slime_proto::zenoh_service_client as wire;
use slime_rt::console_line::Line;
use slime_rt::{exit, monotonic_frequency, monotonic_read, resolve_binding, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"beta";
const RING_BASE: u64 = 0x0000_001e_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;
const SAMPLES: i64 = 4;
const PAYLOAD_BYTES: usize = 12;
const DEADLINE_MS: i64 = 15_000;

fn main(_: u32) {
    let rate = monotonic_frequency().unwrap_or_else(|_| fail(b"clock rate"));
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let clock = TickClock::new(rate, base).unwrap_or_else(|_| fail(b"clock rate too slow"));
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the Zenoh service.
    let mut io = unsafe {
        ClientIo::attach(
            binding(b"beta-zenoh-control"),
            binding(b"beta-zenoh-provision"),
            RING_BASE,
            DATA_BASE,
        )
    }
    .unwrap_or_else(|_| fail(b"attach"));
    if io.rows() != 1 {
        fail(b"rows");
    }
    let mut taken = 0i64;
    let mut out = [0u8; PAYLOAD_BYTES];
    while taken < SAMPLES {
        let now = clock.millis(monotonic_read().unwrap_or_else(|_| fail(b"clock read")));
        if now >= DEADLINE_MS {
            fail(b"deadline");
        }
        let reply = io.take(&mut out).unwrap_or_else(|_| fail(b"take"));
        match reply.item {
            Item::Sample {
                row, sequence, len, ..
            } => {
                if row != 0 || sequence != taken || len != PAYLOAD_BYTES {
                    fail(b"sample");
                }
                if out != [taken as u8; PAYLOAD_BYTES] {
                    fail(b"payload");
                }
                taken += 1;
            }
            Item::None => yield_now(),
            Item::Loss { .. } => fail(b"loss"),
        }
    }
    // The grant gives this holder the key to subscribe to and not to publish on.
    let refusal = io
        .publish(0, 0, &[0u8])
        .unwrap_or_else(|_| fail(b"refusal exchange"));
    if refusal.status != wire::STATUS_DENIED as i32 || refusal.reached != 0 {
        fail(b"refusal result");
    }
    io.finish().unwrap_or_else(|_| fail(b"detach"));
    exit(0)
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
