#![no_std]
#![no_main]

//! A component the PCI binding plane grants nothing. Each hardware request it
//! makes names a slot it does not hold, so the kernel refuses it; this
//! component reports the refusals and must not fault.

use slime_rt::console_line::Line;
use slime_rt::{exit, io_device_bind, io_irq_ack, io_mmio_map};

slime_rt::entry!(main);

fn main(_: u32) {
    let mut device_denials = 0;
    let mut mmio_denials = 0;
    let mut interrupt_denials = 0;

    if io_device_bind(0).is_ok() {
        fail(b"device bind");
    }
    device_denials += 1;
    if io_mmio_map(0, 1, 1, 0x0000_0015_0000_0000, 0, 0x4000).is_ok() {
        fail(b"mmio map");
    }
    mmio_denials += 1;
    if io_irq_ack(2, 1, 0).is_ok() {
        fail(b"irq ack");
    }
    interrupt_denials += 1;

    Line::<256>::new()
        .bytes(b"[pci-intruder] denied device=")
        .decimal(device_denials)
        .bytes(b" mmio=")
        .decimal(mmio_denials)
        .bytes(b" interrupt=")
        .decimal(interrupt_denials)
        .bytes(b"\n")
        .emit();
    exit(0)
}

fn fail(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[pci-intruder] fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}
