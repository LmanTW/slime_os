#![no_std]
#![no_main]

//! A holder of the Zenoh service that attaches, takes one subscription row and then faults. The service learns of the
//! death through the supervision handle the generation declares for this holder, and reclaims the holder's session.

use slime_components::zenoh_service_client::ClientIo;
use slime_rt::console_line::Line;
use slime_rt::{exit, resolve_binding};

slime_rt::entry!(main);

const NAME: &[u8] = b"victim";
const RING_BASE: u64 = 0x0000_001e_0000_0000;
const DATA_BASE: u64 = RING_BASE + 4096;

fn main(_: u32) {
    // SAFETY: these distinct page-aligned regions are reserved solely for this adapter, and the two declared
    // endpoints belong to the Zenoh service.
    let io = unsafe {
        ClientIo::attach(
            binding(b"victim-zenoh-control"),
            binding(b"victim-zenoh-provision"),
            RING_BASE,
            DATA_BASE,
        )
    }
    .unwrap_or_else(|_| fail(b"attach"));
    if io.rows() != 1 {
        fail(b"rows");
    }
    Line::<128>::new()
        .bytes(b"[victim] attached, faulting now\n")
        .emit();
    // SAFETY: the holder faults on purpose, so that the service observes a death it did not ask for. Address zero is
    // never mapped in a component's address space.
    unsafe { (core::ptr::null_mut::<u64>()).write_volatile(0x5a17) }
    exit(1)
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
