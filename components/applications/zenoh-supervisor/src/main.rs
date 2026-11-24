#![no_std]
#![no_main]

//! The owner of a composition that runs the Zenoh service with a holder that faults.
//!
//! A supervision handle must be one the holder of the declaring binding obtained from its owner. This component spawns the
//! holders, the service and its peer, derives a handle for the holder that will fault, and gives the service that handle at
//! spawn. It spawns the publisher only after the faulting holder has terminated, so the service has seen the death before
//! the first publication arrives. Each child's end is read through its own handle.

use boot_contracts::generation::RIGHT_SUPERVISE;
use slime_rt::console_line::Line;
use slime_rt::{SpawnGrant, Termination, exit, resolve_binding, supervision_status, yield_now};

slime_rt::entry!(main);

const NAME: &[u8] = b"zenoh-supervisor";
/// Polls a child's handle. The composition's own deadline bounds the whole run, so this loop waits without a limit.
fn wait_for(handle: u32) -> Termination {
    loop {
        match supervision_status(handle) {
            Ok(Some(outcome)) => return outcome,
            Ok(None) => yield_now(),
            Err(_) => fail(b"supervision status"),
        }
    }
}

fn spawn(executable: &[u8], grants: &[SpawnGrant]) -> u32 {
    let slot = resolve_binding(executable).unwrap_or_else(|_| fail(b"executable"));
    slime_rt::spawn(slot, grants)
        .unwrap_or_else(|_| fail(b"spawn"))
        .supervision_slot
}

fn main(_: u32) {
    let network = spawn(b"zenoh-network-executable", &[]);
    let peer = spawn(b"zenoh-peer-executable", &[]);
    let victim = spawn(b"zenoh-victim-executable", &[]);
    let beta = spawn(b"zenoh-beta-executable", &[]);
    let watch = slime_rt::supervision_derive(victim).unwrap_or_else(|_| fail(b"victim watch"));
    let service = spawn(
        b"zenoh-service-executable",
        &[SpawnGrant {
            slot: watch,
            rights: RIGHT_SUPERVISE,
        }],
    );
    let _ = slime_rt::cap_drop(watch);

    let outcome = wait_for(victim);
    if !matches!(outcome, Termination::Fault(_)) {
        fail(b"victim did not fault");
    }
    say(b"[zenoh-supervisor] holder victim terminated cause=fault\n");

    let alpha = spawn(b"zenoh-alpha-executable", &[]);
    for (label, handle) in [
        (&b"alpha"[..], alpha),
        (&b"beta"[..], beta),
        (&b"service"[..], service),
        (&b"peer"[..], peer),
        (&b"network"[..], network),
    ] {
        if wait_for(handle) != Termination::Exit(0) {
            Line::<128>::new()
                .bytes(b"[zenoh-supervisor] fail: ")
                .bytes(label)
                .bytes(b" did not exit 0\n")
                .emit();
            exit(1)
        }
    }
    say(b"[zenoh-supervisor] survivors exited cleanly\n");
    exit(0)
}

fn say(text: &[u8]) {
    Line::<128>::new().bytes(text).emit();
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
