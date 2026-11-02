#![no_std]
#![no_main]

use core::ptr;
use core::sync::atomic::{Ordering, fence};

use boot_contracts::block_authority::{self, BlockAuthority};
use slime_components::virtio_mmio::{
    self, DESC_F_NEXT, DESC_F_WRITE, MediatedMmio, observe_used, publish_available,
    used_descriptor_slot, used_ring_progress, write_descriptor, write_u16,
};
use slime_proto::block_v2::{
    self, DEVICE_STATUS_IO_ERR, DEVICE_STATUS_OK, DEVICE_STATUS_UNSUPPORTED, WireBlockReply,
    WireBlockRequest,
};
use slime_proto::io_queue::{
    self, REQUEST_PAYLOAD_BYTES, STATUS_BAD_RIGHTS, STATUS_BAD_SLICE, STATUS_DEVICE_ERROR,
    STATUS_MALFORMED, STATUS_OK, STATUS_UNSUPPORTED,
};
use slime_proto::io_queue_ring::{Outstanding, Queue, QueueError};
use slime_proto::{valid_block_v2_request, valid_buffer_slice};
use slime_rt::console_line::Line;
use slime_rt::{
    DmaDirection, DmaMapping, ERR_SUCCESS, MAX_CAPS_PER_MSG, MAX_MSG, block_ring_authority_read,
    capability_import, debug_write, exit, io_device_bind, io_dma_map, io_queue_map,
    io_request_begin, io_request_settle, notification_signal, resolve_binding,
    shared_buffer_loan_map, yield_now,
};

slime_rt::entry!(main);

const PEER_SLOT: u32 = 0;
const DEVICE_SLOT: u32 = 1;
const MMIO_SLOT: u32 = 2;
const DMA_SLOT: u32 = 4;
const IO0_BASE: u64 = 0x0000_0020_0000_0000;
const DATA_BASE: u64 = 0x0000_0020_0001_0000;
const DEVICE_QUEUE_BASE: u64 = 0x0000_0020_0003_0000;
const PAGE: u64 = 4096;
const IO0_BYTES: u64 = 4096;
const DATA_BYTES: u64 = 8 * PAGE;
const DEVICE_QUEUE_PAGES: u32 = 4;
const IO0_SLOTS: usize = 8;
const VIRTQUEUE_SIZE: usize = 16;
const AVAIL_OFFSET: usize = VIRTQUEUE_SIZE * 16;
const USED_OFFSET: usize = 0x1000;
const CONTROL_OFFSET: usize = 0x2000;
const CONTROL_STRIDE: usize = 32;
const VIRTIO_DEVICE_BLOCK: u32 = 2;
const COMPLETION_POLLS: u32 = 100_000_000;
/// Which IO0 ring this driver's client uses. One driver instance serves one
/// ring; a client with different rights uses a different ring, in a different
/// instance.
///
/// The *device* is deliberately not a constant here. It comes from the root's
/// bind answer, because a plane with two disks declares this executable twice
/// and both instances' typed capabilities carry the same positional byte — so
/// the binary cannot know which disk it holds (B84).
const RING_INDEX: u32 = 0;
/// Authority rows one read may return. The generation declares at most one ring
/// per client per device, and no plane wires more clients than this.
const MAX_AUTHORITY_ROWS: usize = 8;

fn main(_startup_arg: u32) {
    // Resolved by role and ordinal, not by grant name. A plane with two disks
    // declares this service twice -- IO1 grants one device per driver instance
    // -- and notification grant names are globally unique with exactly one
    // waiter each, so the two instances are necessarily bound to
    // differently-named grants. A driver naming one grant would serve only
    // whichever instance received it. The ordinal is over this instance's own
    // bindings by ascending slot, so the composition fixes the meaning:
    // wait #0 is requests, signal #0 completions, signal #1 state changes.
    let request_ready = binding(b"notification:@0+wait");
    let completion_ready = binding(b"notification:@0+signal");
    let state_changed = binding(b"notification:@1+signal");
    let device = io_device_bind(DEVICE_SLOT).unwrap_or_else(|_| fail(b"device bind"));
    let mmio = MediatedMmio::new(DEVICE_SLOT, MMIO_SLOT, device.epoch);
    let queue_dma = io_queue_map(
        DMA_SLOT,
        device.epoch,
        DEVICE_QUEUE_BASE,
        DEVICE_QUEUE_PAGES,
    )
    .unwrap_or_else(|_| fail(b"device queue map"));
    debug_write(b"[virtio-blk-driver] mmio mechanism=mediated-bounded-read32-write32\n");
    let handshake = mmio
        .begin(VIRTIO_DEVICE_BLOCK)
        .unwrap_or_else(|_| fail(b"virtio handshake"));
    handshake
        .configure_queue(
            0,
            VIRTQUEUE_SIZE as u16,
            PAGE as u32,
            PAGE as u32,
            queue_dma.iova,
        )
        .unwrap_or_else(|_| fail(b"virtqueue setup"));
    let mmio = handshake.finish();
    let capacity = read_capacity(mmio);

    let (io0_loan, data_loan) = receive_loans();
    if shared_buffer_loan_map(io0_loan, IO0_BASE, 0, IO0_BYTES) != ERR_SUCCESS
        || shared_buffer_loan_map(data_loan, DATA_BASE, 0, DATA_BYTES) != ERR_SUCCESS
    {
        fail(b"loan map");
    }
    let data_read = io_dma_map(DMA_SLOT, data_loan, device.epoch, DmaDirection::DeviceRead)
        .unwrap_or_else(|_| fail(b"device-read dma"));
    let data_write = io_dma_map(DMA_SLOT, data_loan, device.epoch, DmaDirection::DeviceWrite)
        .unwrap_or_else(|_| fail(b"device-write dma"));
    let io0_bytes =
        unsafe { core::slice::from_raw_parts_mut(IO0_BASE as *mut u8, IO0_BYTES as usize) };
    let mut queue = Queue::attach(io0_bytes, IO0_SLOTS).unwrap_or_else(|_| fail(b"io0 attach"));
    let mut outstanding = Outstanding::<IO0_SLOTS>::new(queue.epoch());
    // Read before announcing readiness: a driver that cannot tell a read-only
    // ring from a read-write one must not accept a request, so this refuses the
    // boot rather than serving without the gate.
    let authority = Authority::read();
    // The rights this driver's own ring holds, as the table states them: a read-only data volume and
    // a read-write store differ here, and a gate reads this line rather than trusting its client.
    Line::<128>::new()
        .bytes(b"[virtio-blk-driver] authority rings=")
        .decimal(authority.table().ring_count() as u64)
        .bytes(b" rights=")
        .bytes(ring_rights(&authority, device.device, RING_INDEX))
        .bytes(b" source=generation\n")
        .emit();
    send_ready(capacity);
    Line::<128>::new()
        .bytes(b"[virtio-blk-driver] ready capacity=")
        .decimal(capacity)
        .bytes(b" epoch=")
        .decimal(device.epoch)
        .bytes(b"\n")
        .emit();

    // Serve until the peer says stop. B83's synchronous clients submit one
    // request per signal and wait for that completion before the next, so a
    // single drain pass would answer the first and leave the rest unanswered.
    // The batch client (`io-block-probe`) is served identically: its whole set
    // is provisioned behind one signal and one drain empties it.
    //
    // Both channels are *polled*, not waited on. Requests arrive on the
    // notification and the shutdown command on the endpoint, and this driver
    // has no wait set spanning the two: blocking on either one makes the other
    // undeliverable. Parking in `notification_wait` leaves a client's blocking
    // shutdown send with no receiver, and parking in `recv` leaves a later
    // request's signal latched with nobody to observe it. Polling both and
    // yielding is what lets one thread serve two sources.
    //
    // The shutdown is a call: a non-blocking receive still completes against a
    // caller already parked on the endpoint, so the client blocks and this side
    // polls. The reply goes out only after the final drain below, because the
    // client exits as soon as the call returns and the root then reclaims the
    // ring this driver is draining.
    //
    // The virtqueue used-ring cursor, owned across every drain: the index is
    // absolute and monotonic, so it cannot be re-derived per pass.
    let mut used = 0u16;
    let mut unanswerable_requests = 0u64;
    let device = Device {
        mmio,
        queue_dma,
        data_read,
        data_write,
        capacity,
        completion_ready,
        authority: &authority,
        // The generation's answer, zero-based, exactly as declared in both the
        // IO1 budget and the authority table. Two instances of a two-disk plane
        // run these same bytes and differ only in what the root tells them.
        device_index: device.device,
        ring_index: RING_INDEX,
    };
    loop {
        match slime_rt::notification_poll(request_ready) {
            Ok(Some(_)) => drain(
                &mut queue,
                &mut outstanding,
                &device,
                &mut used,
                &mut unanswerable_requests,
            ),
            Ok(None) => {}
            Err(_) => peer_dead(
                &mut queue,
                &mut outstanding,
                completion_ready,
                state_changed,
            ),
        }
        match peer_command() {
            PeerCommand::None => {}
            PeerCommand::Shutdown => {
                // A final drain, on a *real* shutdown only. The poll and the
                // receive are not one atomic step, so a request published
                // between them is invisible to the poll above; without this the
                // driver could exit leaving a live submission with no
                // completion and its lease unsettled, which is exactly the leak
                // this substrate exists to prevent.
                //
                // It converges because the client is synchronous: submit and
                // shutdown are the same thread, so nothing can be published
                // after the shutdown send.
                drain(
                    &mut queue,
                    &mut outstanding,
                    &device,
                    &mut used,
                    &mut unanswerable_requests,
                );
                // The marker precedes the reply so that it also precedes
                // everything the client prints after its call returns: the
                // plane checkers pin that order, and a reply first would leave
                // it to the scheduler.
                debug_write(b"[virtio-blk-driver] peer complete, exiting\n");
                // Only now may the client go: it is parked in its call until
                // this reply, so its loans outlive every access above.
                let _ = slime_rt::reply(&[1]);
                break;
            }
            // Peer gone is NOT shutdown, and draining here would be a
            // use-after-free: the root unmaps this driver's IO0 loan while
            // reclaiming the dead client, so the ring bytes and its leases are
            // already gone. `peer_dead` settles what it can and marks the ring
            // `DRIVER_DEAD`, which is how a surviving client learns no further
            // completion is coming instead of parking on a wait forever.
            PeerCommand::PeerGone => peer_dead(
                &mut queue,
                &mut outstanding,
                completion_ready,
                state_changed,
            ),
        }
        yield_now();
    }
    exit(0);
}

/// What the peer endpoint is telling this driver.
///
/// Three answers, not two. Collapsing "the client asked me to stop" into "the
/// client is gone" made the shutdown drain run after the root had already
/// reclaimed the client and unmapped this driver's ring.
enum PeerCommand {
    None,
    Shutdown,
    PeerGone,
}

/// Poll the peer endpoint without blocking, so the request notification stays
/// observable.
fn peer_command() -> PeerCommand {
    let mut message = [0u8; MAX_MSG];
    let mut caps = [0u64; MAX_CAPS_PER_MSG];
    match slime_rt::recv(PEER_SLOT, &mut message, &mut caps) {
        slime_rt::ERR_WOULDBLOCK => PeerCommand::None,
        1 if message[0] == 1 => PeerCommand::Shutdown,
        result if result < 0 => PeerCommand::PeerGone,
        _ => fail(b"shutdown command"),
    }
}

/// Everything `drain` needs that does not change between requests.
///
/// A struct rather than eleven positional arguments: the mappings, the two DMA
/// directions, and the authority triple are each easy to transpose at a call
/// site, and a transposed `data_read`/`data_write` would program the device to
/// write into a buffer it was meant to read.
struct Device<'a> {
    mmio: MediatedMmio,
    queue_dma: DmaMapping,
    data_read: DmaMapping,
    data_write: DmaMapping,
    capacity: u64,
    completion_ready: u32,
    authority: &'a Authority,
    /// Which device and which IO0 ring this driver serves. The pair the
    /// authority table is keyed by, taken from this driver's own declared
    /// bindings rather than from any submission: a request naming its own ring
    /// would be a client asserting its own authority.
    device_index: u32,
    ring_index: u32,
}

fn drain(
    queue: &mut Queue<'_>,
    outstanding: &mut Outstanding<IO0_SLOTS>,
    device: &Device<'_>,
    used: &mut u16,
    unanswerable_requests: &mut u64,
) {
    let Device {
        mmio,
        queue_dma,
        data_read,
        data_write,
        capacity,
        completion_ready,
        authority,
        device_index,
        ring_index,
    } = *device;
    let mut payload = [0u8; REQUEST_PAYLOAD_BYTES];
    loop {
        let submission = match queue.take_request(&mut payload, DATA_BYTES) {
            Ok(value) => value,
            Err(error) if error.error == QueueError::Empty => break,
            Err(error) => {
                if error.request_id == 0 {
                    *unanswerable_requests += 1;
                    Line::<128>::new()
                        .bytes(b"[virtio-blk-driver] unanswerable requests=")
                        .decimal(*unanswerable_requests)
                        .bytes(b"\n")
                        .emit();
                } else {
                    complete(
                        queue,
                        error.request_id,
                        STATUS_MALFORMED,
                        0,
                        malformed_reply(0),
                        completion_ready,
                    );
                }
                continue;
            }
        };
        let Some(request) = WireBlockRequest::decode(&payload[..submission.payload_len]) else {
            complete(
                queue,
                submission.request_id,
                STATUS_MALFORMED,
                0,
                malformed_reply(0),
                completion_ready,
            );
            continue;
        };
        if !valid_block_v2_request(&request)
            || !slice_matches(&submission.slice, &request)
            || !valid_buffer_slice(&submission.slice, DATA_BYTES)
        {
            complete(
                queue,
                submission.request_id,
                STATUS_BAD_SLICE,
                0,
                malformed_reply(request.op),
                completion_ready,
            );
            continue;
        }
        // Shape first, then authority. A request whose magic, opcode, or slice
        // is wrong is malformed before it is unauthorized, and answering it
        // `STATUS_BAD_RIGHTS` would tell a caller its bytes were well-formed.
        //
        // This is the gate the root applied per request against the
        // badge-derived caller's own capability. Here it is the ring's declared
        // authority instead, because a ring is shared memory and a submission
        // carries no rights identity to derive one from.
        if !authority.allows(device_index, ring_index, &request) {
            // Reported by the component that enforces the ring's authority, so a gate does not take
            // the refused client's word for it.
            Line::<128>::new()
                .bytes(b"[virtio-blk-driver] refused ")
                .bytes(match request.op {
                    block_v2::OP_READ => b"read" as &[u8],
                    block_v2::OP_WRITE => b"write",
                    block_v2::OP_FLUSH => b"flush",
                    block_v2::OP_GEOMETRY => b"geometry",
                    _ => b"other",
                })
                .bytes(b" ring=")
                .decimal(u64::from(ring_index))
                .bytes(b" rights=")
                .bytes(ring_rights(authority, device_index, ring_index))
                .bytes(b"\n")
                .emit();
            refuse_bad_rights(queue, submission.request_id, request.op, completion_ready);
            continue;
        }
        if request.op == block_v2::OP_GEOMETRY {
            complete(
                queue,
                submission.request_id,
                STATUS_OK,
                0,
                reply(request.op, 0, DEVICE_STATUS_OK, capacity),
                completion_ready,
            );
            continue;
        }
        if request.op != block_v2::OP_FLUSH
            && request
                .lba
                .checked_add(u64::from(request.sector_count))
                .is_none_or(|end| end > capacity)
        {
            complete(
                queue,
                submission.request_id,
                STATUS_DEVICE_ERROR,
                0,
                reply(request.op, 0, DEVICE_STATUS_IO_ERR, capacity),
                completion_ready,
            );
            continue;
        }
        let mapping = if request.op == block_v2::OP_READ {
            data_write
        } else {
            data_read
        };
        outstanding
            .admit(
                submission.request_id,
                submission.slice.lease,
                submission.slice.length,
            )
            .unwrap_or_else(|_| fail(b"outstanding admit"));
        outstanding
            .start(submission.request_id)
            .unwrap_or_else(|_| fail(b"outstanding start"));
        if io_request_begin(DMA_SLOT, mapping, submission.request_id) != ERR_SUCCESS {
            settle_device_error(
                queue,
                outstanding,
                submission.request_id,
                request.op,
                completion_ready,
            );
            continue;
        }
        let outcome = execute(
            mmio,
            queue_dma,
            mapping,
            submission.slice.offset,
            &request,
            used,
        );
        let _ = io_request_settle(DMA_SLOT, mapping, submission.request_id);
        let settled = outstanding
            .settle(submission.request_id, outcome.status)
            .unwrap_or_else(|_| fail(b"outstanding settle"));
        if settled.lease != submission.slice.lease {
            fail(b"lease identity");
        }
        complete(
            queue,
            submission.request_id,
            outcome.status,
            outcome.bytes,
            outcome.payload,
            completion_ready,
        );
    }
}

struct Outcome {
    status: u32,
    bytes: u64,
    payload: [u8; block_v2::REPLY_LEN],
}

/// Program one request and wait for the device to retire it.
///
/// `used` is the driver-owned used-ring cursor. This driver publishes exactly
/// one chain at a time, so a device may advance the index by at most one. The
/// used entry must then name head zero and report exactly the bytes writable by
/// that chain; every other device-written value terminally refuses this request.
/// The cursor persists across requests because the used index is absolute and
/// monotonic.
fn execute(
    mmio: MediatedMmio,
    queue_dma: DmaMapping,
    data_dma: DmaMapping,
    slice_offset: u64,
    request: &WireBlockRequest,
    used: &mut u16,
) -> Outcome {
    let queue = unsafe {
        core::slice::from_raw_parts_mut(
            DEVICE_QUEUE_BASE as *mut u8,
            DEVICE_QUEUE_PAGES as usize * PAGE as usize,
        )
    };
    let kind = match request.op {
        block_v2::OP_READ => 0u32,
        block_v2::OP_WRITE => 1u32,
        block_v2::OP_FLUSH => 4u32,
        _ => {
            return Outcome {
                status: STATUS_UNSUPPORTED,
                bytes: 0,
                payload: reply(request.op, 0, DEVICE_STATUS_UNSUPPORTED, 0),
            };
        }
    };
    let slot = 0usize;
    let control = CONTROL_OFFSET + slot * CONTROL_STRIDE;
    queue[control..control + 4].copy_from_slice(&kind.to_le_bytes());
    queue[control + 8..control + 16].copy_from_slice(&request.lba.to_le_bytes());
    queue[control + 16] = 0xff;
    let control_iova = queue_dma.iova + control as u64;
    let bytes = request.sector_count as u64 * block_v2::SECTOR_BYTES as u64;
    // FLUSH moves no bytes, so it is a two-descriptor chain. A zero-length data
    // descriptor is not a smaller transfer -- virtio rejects it -- and the batch
    // client never issued a flush, so this path had no coverage until a
    // synchronous client used it.
    let chained = if request.op == block_v2::OP_FLUSH {
        write_descriptor(queue, 0, 0, control_iova, 16, DESC_F_NEXT, 1)
            && write_descriptor(queue, 0, 1, control_iova + 16, 1, DESC_F_WRITE, 0)
    } else {
        write_descriptor(queue, 0, 0, control_iova, 16, DESC_F_NEXT, 1)
            && write_descriptor(
                queue,
                0,
                1,
                data_dma.iova + slice_offset,
                bytes as u32,
                DESC_F_NEXT
                    | if request.op == block_v2::OP_READ {
                        DESC_F_WRITE
                    } else {
                        0
                    },
                2,
            )
            && write_descriptor(queue, 0, 2, control_iova + 16, 1, DESC_F_WRITE, 0)
    };
    if !chained
        || !write_u16(
            queue,
            AVAIL_OFFSET + 4 + 2 * (*used as usize % VIRTQUEUE_SIZE),
            0,
        )
        || !publish_available(queue, AVAIL_OFFSET + 2, used.wrapping_add(1))
    {
        return Outcome {
            status: STATUS_DEVICE_ERROR,
            bytes: 0,
            payload: reply(request.op, 0, DEVICE_STATUS_IO_ERR, 1),
        };
    }
    mmio.notify_queue(0);
    for _ in 0..COMPLETION_POLLS {
        let Some(published) = observe_used(queue, USED_OFFSET + 2) else {
            return device_error(mmio, request.op, 4);
        };
        match used_ring_progress(published, *used, 1) {
            None => return device_error(mmio, request.op, 5),
            Some(0) => {}
            Some(_) => {
                let entry = USED_OFFSET + 4 + (usize::from(*used) % VIRTQUEUE_SIZE) * 8;
                let id = unsafe {
                    u32::from_le(ptr::read_volatile(queue.as_ptr().add(entry).cast::<u32>()))
                };
                let reported = unsafe {
                    u32::from_le(ptr::read_volatile(
                        queue.as_ptr().add(entry + 4).cast::<u32>(),
                    ))
                };
                *used = used.wrapping_add(1);
                let expected = if request.op == block_v2::OP_READ {
                    bytes
                        .checked_add(1)
                        .and_then(|value| u32::try_from(value).ok())
                } else {
                    Some(1)
                };
                if used_descriptor_slot(id, 1) != Some(slot) || expected != Some(reported) {
                    return device_error(mmio, request.op, 6);
                }
                mmio.acknowledge_interrupts();
                fence(Ordering::Acquire);
                let status = unsafe { ptr::read_volatile(queue.as_ptr().add(control + 16)) };
                return match status {
                    value if u32::from(value) == DEVICE_STATUS_OK => Outcome {
                        status: STATUS_OK,
                        bytes,
                        payload: reply(request.op, request.sector_count, DEVICE_STATUS_OK, 0),
                    },
                    value if u32::from(value) == DEVICE_STATUS_IO_ERR => Outcome {
                        status: STATUS_DEVICE_ERROR,
                        bytes: 0,
                        payload: reply(request.op, 0, DEVICE_STATUS_IO_ERR, 0),
                    },
                    value if u32::from(value) == DEVICE_STATUS_UNSUPPORTED => Outcome {
                        status: STATUS_DEVICE_ERROR,
                        bytes: 0,
                        payload: reply(request.op, 0, DEVICE_STATUS_UNSUPPORTED, 0),
                    },
                    value => Outcome {
                        status: STATUS_DEVICE_ERROR,
                        bytes: 0,
                        payload: reply(request.op, 0, DEVICE_STATUS_IO_ERR, u64::from(value)),
                    },
                };
            }
        }
        yield_now();
    }
    device_error(mmio, request.op, 2)
}

fn device_error(mmio: MediatedMmio, op: u8, detail: u64) -> Outcome {
    mmio.fail();
    Outcome {
        status: STATUS_DEVICE_ERROR,
        bytes: 0,
        payload: reply(op, 0, DEVICE_STATUS_IO_ERR, detail),
    }
}

fn slice_matches(slice: &io_queue::WireBufferSlice, request: &WireBlockRequest) -> bool {
    match request.op {
        block_v2::OP_READ => {
            slice.direction == io_queue::DIRECTION_DEVICE_WRITE
                && slice.length == u64::from(request.sector_count) * block_v2::SECTOR_BYTES as u64
        }
        block_v2::OP_WRITE => {
            slice.direction == io_queue::DIRECTION_DEVICE_READ
                && slice.length == u64::from(request.sector_count) * block_v2::SECTOR_BYTES as u64
        }
        block_v2::OP_FLUSH | block_v2::OP_GEOMETRY => slice.direction == io_queue::DIRECTION_NONE,
        _ => false,
    }
}

/// The authenticated per-ring authority this driver serves (B83).
///
/// Read once at start from the generation resource, through the root's
/// identity-gated paged path. Held decoded for the driver's lifetime because
/// the generation cannot change under a running driver: a new generation is a
/// new boot, and a restart re-reads it under a fresh epoch.
struct Authority {
    bytes: [u8; block_authority::HEADER_BYTES + MAX_AUTHORITY_ROWS * block_authority::ENTRY_BYTES],
    len: usize,
}

impl Authority {
    /// Read and validate the table. A generation declaring none is fatal rather
    /// than permissive: a driver that cannot tell a read-only ring from a
    /// read-write one must not serve either.
    fn read() -> Self {
        let mut bytes = [0u8; block_authority::HEADER_BYTES
            + MAX_AUTHORITY_ROWS * block_authority::ENTRY_BYTES];
        bytes[..8].copy_from_slice(&block_authority::MAGIC);
        bytes[8..12].copy_from_slice(&block_authority::FORMAT_VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&(block_authority::HEADER_BYTES as u32).to_le_bytes());
        let rows = block_ring_authority_read(0, &mut bytes[block_authority::HEADER_BYTES..])
            .unwrap_or_else(|_| fail(b"block authority read"));
        let len = block_authority::HEADER_BYTES + rows * block_authority::ENTRY_BYTES;
        bytes[24..28].copy_from_slice(&(rows as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&(len as u32).to_le_bytes());
        // Decoded here only to refuse a malformed table before serving; the
        // borrow cannot be kept alongside the owning array, so each lookup
        // re-decodes validated bytes.
        BlockAuthority::decode(&bytes[..len]).unwrap_or_else(|_| fail(b"block authority decode"));
        Self { bytes, len }
    }

    fn table(&self) -> BlockAuthority<'_> {
        BlockAuthority::decode(&self.bytes[..self.len]).expect("validated at start")
    }

    /// Whether `ring`, on `device`, may perform `op` over `lba..lba + count`.
    ///
    /// The gate the root used to apply per request against the badge-derived
    /// caller's capability. `GEOMETRY` needs read authority: capacity is
    /// information about the medium, and a ring granted nothing must not learn
    /// it. An unknown opcode is refused here rather than treated as
    /// unauthorized, because it is malformed before it is unauthorized.
    fn allows(&self, device: u32, ring: u32, request: &WireBlockRequest) -> bool {
        let table = self.table();
        let right = match request.op {
            block_v2::OP_READ | block_v2::OP_GEOMETRY => block_authority::Right::Read,
            block_v2::OP_WRITE | block_v2::OP_FLUSH => block_authority::Right::Write,
            _ => return false,
        };
        match request.op {
            // A range request is bounded by the ring's declared sector ceiling
            // as well as its rights, so a granted ring cannot reach a sector
            // the generation did not give it.
            block_v2::OP_READ | block_v2::OP_WRITE => {
                table.authorizes_range(device, ring, right, request.lba, request.sector_count)
            }
            _ => table.authorizes(device, ring, right),
        }
    }
}

/// The rights the authority table grants one ring, spelled as the driver reports them.
fn ring_rights(authority: &Authority, device: u32, ring: u32) -> &'static [u8] {
    let table = authority.table();
    match (
        table.authorizes(device, ring, block_authority::Right::Read),
        table.authorizes(device, ring, block_authority::Right::Write),
    ) {
        (true, true) => b"read,write",
        (true, false) => b"read",
        (false, true) => b"write",
        (false, false) => b"none",
    }
}

/// Answer an unauthorized submission.
///
/// No settlement, because the request was refused *before* `admit`: it holds no
/// outstanding entry and retains no lease, so there is nothing to release. This
/// is the same shape the malformed and bad-slice refusals use, and it is why the
/// authority gate sits ahead of admission — an unauthorized request must not
/// charge an outstanding-request slot against the driver's IO1 budget.
fn refuse_bad_rights(queue: &mut Queue<'_>, request_id: u64, op: u8, completion_ready: u32) {
    complete(
        queue,
        request_id,
        STATUS_BAD_RIGHTS,
        0,
        reply(op, 0, DEVICE_STATUS_IO_ERR, 0),
        completion_ready,
    );
}

fn settle_device_error(
    queue: &mut Queue<'_>,
    outstanding: &mut Outstanding<IO0_SLOTS>,
    request_id: u64,
    op: u8,
    completion_ready: u32,
) {
    outstanding
        .settle(request_id, STATUS_DEVICE_ERROR)
        .unwrap_or_else(|_| fail(b"begin refusal settle"));
    complete(
        queue,
        request_id,
        STATUS_DEVICE_ERROR,
        0,
        reply(op, 0, DEVICE_STATUS_IO_ERR, 3),
        completion_ready,
    );
}

fn complete(
    queue: &mut Queue<'_>,
    request_id: u64,
    status: u32,
    transferred: u64,
    payload: [u8; block_v2::REPLY_LEN],
    signal: u32,
) {
    queue
        .complete(request_id, status, transferred, &payload, false)
        .unwrap_or_else(|_| fail(b"completion publish"));
    if notification_signal(signal) != ERR_SUCCESS {
        fail(b"completion signal");
    }
}

fn reply(op: u8, sectors_done: u32, device_status: u32, detail: u64) -> [u8; block_v2::REPLY_LEN] {
    WireBlockReply {
        magic: block_v2::BLOCK_MAGIC,
        version: block_v2::FORMAT_VERSION,
        op,
        reserved: [0],
        sectors_done,
        device_status,
        detail,
    }
    .encode()
}
fn malformed_reply(op: u8) -> [u8; block_v2::REPLY_LEN] {
    reply(op, 0, DEVICE_STATUS_IO_ERR, 0)
}

fn read_capacity(mmio: MediatedMmio) -> u64 {
    let low = u64::from(mmio.read32(virtio_mmio::register::CONFIG).unwrap_or(0));
    let high = u64::from(mmio.read32(virtio_mmio::register::CONFIG + 4).unwrap_or(0));
    (high << 32) | low
}

fn receive_loans() -> (u32, u32) {
    let mut message = [0u8; MAX_MSG];
    let mut caps = [0u64; MAX_CAPS_PER_MSG];
    let mut loans = [0u32; 2];
    for loan in &mut loans {
        loop {
            match slime_rt::recv(PEER_SLOT, &mut message, &mut caps) {
                slime_rt::ERR_WOULDBLOCK => yield_now(),
                result if result < 0 => fail(b"loan receive"),
                _ => {
                    *loan = capability_import().unwrap_or_else(|_| fail(b"loan import"));
                    break;
                }
            }
        }
    }
    (loans[0], loans[1])
}

fn send_ready(capacity: u64) {
    loop {
        match slime_rt::send(PEER_SLOT, &capacity.to_le_bytes(), &[]) {
            slime_rt::ERR_WOULDBLOCK => yield_now(),
            ERR_SUCCESS => return,
            _ => fail(b"ready send"),
        }
    }
}

fn peer_dead(
    queue: &mut Queue<'_>,
    outstanding: &mut Outstanding<IO0_SLOTS>,
    completion_ready: u32,
    state_changed: u32,
) -> ! {
    queue.mark_driver_dead();
    let _ = outstanding.settle_all(io_queue::STATUS_PEER_DEAD, |entry| {
        let _ = queue.complete(entry.request_id, io_queue::STATUS_PEER_DEAD, 0, &[], true);
    });
    let _ = notification_signal(completion_ready);
    let _ = notification_signal(state_changed);
    exit(0)
}

fn binding(name: &[u8]) -> u32 {
    resolve_binding(name).unwrap_or_else(|_| fail(b"notification binding"))
}
fn fail(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[virtio-blk-driver] fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    exit(1)
}
