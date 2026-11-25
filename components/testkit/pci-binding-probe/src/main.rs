#![no_std]
#![no_main]

//! The PCI binding plane's probe: a supervisor that spawns a driver worker
//! holding one PCI function's device, MMIO and interrupt grants, and restarts
//! it once after a deliberate fault.
//!
//! The worker never learns the function's address or the BAR's physical
//! address. It maps BAR 0 as granted, reads two xHCI capability words, and in
//! its first incarnation asks for the first granule past the BAR, which the
//! root refuses.

use slime_rt::console_line::Line;
use slime_rt::{
    SpawnGrant, Termination, debug_write, exit, io_device_bind, io_irq_ack, io_mmio_map,
    lifecycle_restart_admit, resolve_binding, spawn, supervision_status, yield_now,
};

slime_rt::entry!(main);

const DEVICE_SLOT: u32 = 0;
const REGION_SLOT: u32 = 1;
const IRQ_SLOT: u32 = 2;
const RIGHT_MAP_MMIO: u64 = 16;
const RIGHT_IRQ_ACK: u64 = 128;
const BASE: u64 = 0x0000_0014_0000_0000;
/// qemu-xhci's BAR 0. The root grants the BAR it sized, so a whole-BAR map
/// that succeeds and a map one granule past it that fails show the grant
/// equals this size.
const BAR_BYTES: u32 = 0x4000;

fn main(_: u32) {
    if let Ok(executable) = resolve_binding(b"pci-worker-executable") {
        run_supervisor(executable)
    }
    run_driver()
}

fn run_supervisor(executable: u32) -> ! {
    let grants = [
        grant(
            resolve_binding(b"pci-device").unwrap_or_else(|_| fail(b"resolve device")),
            RIGHT_MAP_MMIO,
        ),
        grant(
            resolve_binding(b"pci-mmio").unwrap_or_else(|_| fail(b"resolve mmio")),
            RIGHT_MAP_MMIO,
        ),
        grant(
            resolve_binding(b"pci-irq").unwrap_or_else(|_| fail(b"resolve irq")),
            RIGHT_IRQ_ACK,
        ),
    ];
    let first = spawn(executable, &grants).unwrap_or_else(|_| fail(b"initial driver spawn"));
    let subject = slime_rt::supervision_derive(first.supervision_slot)
        .unwrap_or_else(|_| fail(b"derive restart subject"));
    loop {
        match supervision_status(first.supervision_slot) {
            Ok(Some(Termination::Fault(_))) => break,
            Ok(None) => yield_now(),
            _ => fail(b"driver did not fault"),
        }
    }
    debug_write(b"[pci-supervisor] predecessor fault collected\n");
    let admission = lifecycle_restart_admit(subject).unwrap_or_else(|_| fail(b"restart admit"));
    while slime_rt::monotonic_read().is_ok_and(|now| now < admission.ready_at) {
        yield_now();
    }
    let second = spawn(executable, &grants).unwrap_or_else(|_| fail(b"replacement spawn"));
    loop {
        match supervision_status(second.supervision_slot) {
            Ok(Some(Termination::Exit(0))) => break,
            Ok(None) => yield_now(),
            _ => fail(b"replacement failed"),
        }
    }
    debug_write(b"[pci-supervisor] replacement completed\n");
    exit(0)
}

fn run_driver() -> ! {
    let device = io_device_bind(DEVICE_SLOT).unwrap_or_else(|_| fail(b"bind granted device"));
    io_mmio_map(DEVICE_SLOT, REGION_SLOT, device.epoch, BASE, 0, BAR_BYTES)
        .unwrap_or_else(|_| fail(b"map bar 0"));
    io_irq_ack(IRQ_SLOT, device.epoch, 0).unwrap_or_else(|_| fail(b"bind interrupt"));
    Line::<128>::new()
        .bytes(b"[pci-binding-probe] bound bytes=")
        .decimal(u64::from(BAR_BYTES))
        .bytes(b" irqs=1 epoch=")
        .decimal(device.epoch)
        .bytes(b"\n")
        .emit();
    // SAFETY: the root mapped BAR 0 at `BASE` for this task just above; the
    // two words are xHCI capability registers, which a read does not change.
    let (capabilities, structural) = unsafe {
        (
            (BASE as *const u32).read_volatile(),
            ((BASE + 4) as *const u32).read_volatile(),
        )
    };
    Line::<128>::new()
        .bytes(b"[pci-binding-probe] xhci cap=0x")
        .hex_bytes(&capabilities.to_be_bytes())
        .bytes(b" hcsparams1=0x")
        .hex_bytes(&structural.to_be_bytes())
        .bytes(b" epoch=")
        .decimal(device.epoch)
        .bytes(b"\n")
        .emit();
    if device.epoch > 1 {
        debug_write(b"[pci-binding-probe] pci binding plane complete\n");
        exit(0)
    }
    if io_mmio_map(
        DEVICE_SLOT,
        REGION_SLOT,
        device.epoch,
        BASE + u64::from(BAR_BYTES),
        BAR_BYTES,
        0x1000,
    )
    .is_ok()
    {
        fail(b"mmio past bar 0 mapped");
    }
    Line::<128>::new()
        .bytes(b"[pci-binding-probe] mmio beyond bar refused offset=")
        .decimal(u64::from(BAR_BYTES))
        .bytes(b"\n")
        .emit();
    debug_write(b"[pci-binding-probe] faulting with live authority\n");
    // SAFETY: none; the write faults on purpose so the root reclaims a task
    // that still holds its MMIO and interrupt authority.
    unsafe {
        core::ptr::null_mut::<u64>().write_volatile(1);
    }
    fail(b"null write did not fault")
}

const fn grant(slot: u32, rights: u64) -> SpawnGrant {
    SpawnGrant { slot, rights }
}

fn fail(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[pci-binding-probe] fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}
