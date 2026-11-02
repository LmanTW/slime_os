#![no_std]
#![no_main]

//! The data-volume plane's subject: reads a `contracts/data-volume/v1` disk through a read-only block ring.
//!
//! The component validates the volume in the contract's order with `slime_components::data_volume`,
//! streams the frame store through the same ring without holding it, and reports what it read. It then
//! tries one write, which the driver must refuse for the ring's rights. It links no allocator. Every line
//! it prints is judged by `just data_volume_check`; a refused volume prints its class and nothing after
//! it.

use slime_components::block_io::{BlockError, BlockIo};
use slime_components::data_volume::{self, DeviceError, Disk, Error, Refusal};
use slime_proto::block_v2::SECTOR_BYTES;
use slime_proto::io_queue::STATUS_BAD_RIGHTS;
use slime_rt::console_line::Line;

/// Page-aligned addresses in this component's free VSpace range for the ring and its payload window.
const RING_BASE: u64 = 0x0000_001f_0000_0000;
const DATA_BASE: u64 = 0x0000_001f_0001_0000;
const TAG: &[u8] = b"[data-volume-probe] ";

slime_rt::entry!(main);

/// The volume's block device: the block ring, read whole sectors at a time.
struct Ring {
    io: BlockIo<'static>,
    capacity: u64,
}

impl Disk for Ring {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read(&mut self, lba: u64, out: &mut [u8]) -> Result<(), DeviceError> {
        let sectors = (out.len() / SECTOR_BYTES) as u32;
        match self.io.read(lba, out) {
            Ok(reply) if reply.sectors_done == sectors => Ok(()),
            _ => Err(DeviceError),
        }
    }
}

fn binding(name: &[u8]) -> u32 {
    slime_rt::resolve_binding(name).unwrap_or_else(|_| fail(b"binding"))
}

fn fail(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(TAG)
        .bytes(b"fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1);
}

/// A refused volume is a result, not a failure: report its class, release the ring and exit cleanly.
fn refuse(ring: &mut Ring, refusal: Refusal) -> ! {
    Line::<256>::new()
        .bytes(TAG)
        .bytes(b"refused ")
        .bytes(refusal.class().as_bytes())
        .bytes(b"\n")
        .emit();
    let _ = ring.io.shutdown();
    slime_rt::exit(0);
}

fn read_or_refuse<T>(ring: &mut Ring, result: Result<T, Error>) -> T {
    match result {
        Ok(value) => value,
        Err(Error::Refused(refusal)) => refuse(ring, refusal),
        Err(Error::Device) => fail(b"block read"),
    }
}

fn main(_startup_arg: u32) {
    let request_ready = binding(b"notification:io-block-request-ready+signal");
    let completion_ready = binding(b"notification:io-block-completion-ready+wait");
    // SAFETY: both bases are page-aligned addresses in this component's free VSpace range, do not
    // alias each other, and nothing else maps them.
    let io = unsafe {
        BlockIo::attach(
            binding(b"data-volume-probe-buffer-factory"),
            binding(b"data-volume-block-peer"),
            request_ready,
            completion_ready,
            RING_BASE,
            DATA_BASE,
        )
    }
    .unwrap_or_else(|_| fail(b"block attach"));
    let capacity = io.capacity();
    let mut ring = Ring { io, capacity };

    let opened = data_volume::open(&mut ring);
    let volume = read_or_refuse(&mut ring, opened);
    Line::<256>::new()
        .bytes(TAG)
        .bytes(b"volume kind=frame-store bytes=")
        .decimal(volume.payload_bytes)
        .bytes(b" sha256=")
        .hex_bytes(&volume.payload_sha256)
        .bytes(b"\n")
        .emit();
    let read = data_volume::frame_store(&mut ring, &volume);
    let store = read_or_refuse(&mut ring, read);
    Line::<256>::new()
        .bytes(TAG)
        .bytes(b"frames count=")
        .decimal(store.frame_count as u64)
        .bytes(b" period=")
        .decimal(store.frame_period_ns)
        .bytes(b" first=")
        .decimal(store.first_log_time_ns)
        .bytes(b" last=")
        .decimal(store.last_log_time_ns)
        .bytes(b" digest=")
        .hex_bytes(&store.payload_digest)
        .bytes(b"\n")
        .emit();

    // The ring's authority grants reads only. The write must be refused by the driver for its rights,
    // which the driver reports itself; any other answer is a failure.
    match ring.io.write(0, &[0u8; SECTOR_BYTES]) {
        Err(BlockError::Refused { status, .. }) if status == STATUS_BAD_RIGHTS => {
            Line::<256>::new()
                .bytes(TAG)
                .bytes(b"write refused\n")
                .emit();
        }
        _ => fail(b"a write was not refused for the ring's rights"),
    }
    // This crate links no allocator, so an allocation cannot compile: the reader held the volume in
    // its fixed sector and chunk buffers, and the heap it used is zero by construction.
    Line::<256>::new().bytes(TAG).bytes(b"heap used=0\n").emit();
    ring.io
        .shutdown()
        .unwrap_or_else(|_| fail(b"driver shutdown"));
    Line::<256>::new().bytes(TAG).bytes(b"complete\n").emit();
}
