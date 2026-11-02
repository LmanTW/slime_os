//! The holders of the Zenoh service: each one's loans, its control endpoint and its ring, and the loop that serves them.
//!
//! A holder is identified by the control endpoint its request arrived on, and the endpoint is named by the holder, so no
//! request can name another. The loans are shared buffers the service creates and lends, as the network service does
//! for its applications. The holder cannot choose or replace either mapped object.

use crate::{Holders, Link, binding, fail};
use slime_components::tick_clock::TickClock;
use slime_components::zenoh_service::{OverLink, Settled};
use slime_components::zenoh_service_server::{Answer, REQUEST_BYTES, Server, denied};
use slime_proto::io_queue::{self, REQUEST_PAYLOAD_BYTES};
use slime_proto::io_queue_ring::{Outstanding, Queue, QueueError};
use slime_proto::zenoh_service_client as wire;
use slime_proto::zenoh_service_client_wire::{WireServiceCompletion, WireServiceLoan, WireServiceRequest};
use slime_rt::console_line::Line;
use slime_rt::{ERR_SUCCESS, ERR_WOULDBLOCK, MAX_CAPS_PER_MSG, MAX_MSG, monotonic_read, recv, send, yield_now};

const FACTORY_SLOT: u32 = 1;
const BASE: u64 = 0x0000_001a_0000_0000;
const STRIDE: u64 = 0x0001_0000;
const RING_BYTES: usize = wire::RING_BYTES as usize;
const DATA_BYTES: usize = wire::DATA_BYTES as usize;
const QUEUE_SLOTS: usize = wire::QUEUE_SLOTS as usize;
const MAGIC: u32 = wire::SERVICE_MAGIC as u32;
const VERSION: u16 = wire::FORMAT_VERSION as u16;
const SUFFIXES: [&[u8]; 2] = [b"-zenoh-control", b"-zenoh-provision"];

pub struct Names {
    pub bytes: [[u8; 32]; crate::HOLDERS],
    pub lens: [usize; crate::HOLDERS],
    pub count: usize,
}

/// One shared buffer the service owns, mapped at a fixed address and lent to one holder.
struct Region {
    buffer: slime_rt::SharedBuffer,
    base: u64,
    mapped: bool,
    live: bool,
    lease: Option<u64>,
}

impl Region {
    fn create(pages: usize, base: u64, length: usize) -> Result<Self, ()> {
        let buffer = slime_rt::shared_buffer_create(FACTORY_SLOT, pages, true).map_err(|_| ())?;
        let mut region = Self {
            buffer,
            base,
            mapped: false,
            live: true,
            lease: None,
        };
        if slime_rt::shared_buffer_map(buffer.slot, base, 0, length as u64, true) != ERR_SUCCESS {
            return Err(());
        }
        region.mapped = true;
        Ok(region)
    }

    fn delegate(&mut self, peer: u32, role: u8, length: usize) -> Result<(), ()> {
        let loan = slime_rt::shared_buffer_loan(self.buffer.slot, peer, 0, length as u64, true).map_err(|_| ())?;
        self.lease = Some(loan.id);
        let descriptor = WireServiceLoan {
            magic: MAGIC,
            version: VERSION,
            role,
            reserved0: [0; 1],
            buffer: self.buffer.id,
            lease: loan.id,
            length: length as u64,
            reserved: [0; 32],
        };
        if slime_rt::capability_delegate(
            peer,
            loan.slot,
            slime_rt::CapabilityDisposition::Move,
            slime_proto::capability_transfer::OBJECT_KIND_SHARED_BUFFER_LOAN,
            boot_contracts::generation::RIGHT_BUFFER_MAP | boot_contracts::generation::RIGHT_BUFFER_WRITE,
            &descriptor.encode(),
        ) != ERR_SUCCESS
        {
            return Err(());
        }
        Ok(())
    }

    fn release(&mut self) -> bool {
        if !self.live {
            return true;
        }
        self.live = false;
        if let Some(lease) = self.lease.take() {
            let _ = slime_rt::shared_buffer_revoke(self.buffer.slot, lease);
        }
        let mut success = true;
        if self.mapped {
            success &= slime_rt::shared_buffer_unmap(self.buffer.slot, self.base) == ERR_SUCCESS;
            self.mapped = false;
        }
        success &= slime_rt::shared_buffer_release(self.buffer.slot) == ERR_SUCCESS;
        success
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// A holder with a session: its ring, its data page and the requests it has outstanding.
struct Session {
    // The ring view is dropped before its backing regions on every exit.
    queue: Queue<'static>,
    ring: Region,
    data: Region,
    outstanding: Outstanding<{ QUEUE_SLOTS }>,
    last_request: u64,
}

impl Session {
    fn open(index: usize, peer: u32, epoch: u64) -> Result<Self, ()> {
        let base = BASE.checked_add((index as u64).checked_mul(STRIDE).ok_or(())?).ok_or(())?;
        let data_base = base.checked_add(RING_BYTES as u64).ok_or(())?;
        let mut ring = Region::create(wire::RING_PAGES as usize, base, RING_BYTES)?;
        let mut data = Region::create(wire::DATA_PAGES as usize, data_base, DATA_BYTES)?;
        // SAFETY: this index owns a disjoint VSpace range and a fresh buffer. Only the queue view borrows the ring
        // until that view is dropped.
        let bytes = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, RING_BYTES) };
        slime_proto::io_queue_ring::format(bytes, QUEUE_SLOTS, epoch).map_err(|_| ())?;
        ring.delegate(peer, wire::LOAN_ROLE_RING as u8, RING_BYTES)?;
        data.delegate(peer, wire::LOAN_ROLE_DATA as u8, DATA_BYTES)?;
        let queue = Queue::attach(bytes, QUEUE_SLOTS).map_err(|_| ())?;
        let outstanding = Outstanding::new(queue.epoch());
        Ok(Self {
            queue,
            ring,
            data,
            outstanding,
            last_request: 0,
        })
    }

    fn close(mut self) -> bool {
        self.outstanding.settle_all(io_queue::STATUS_PEER_DEAD, |_| {});
        self.queue.mark_driver_dead();
        let (mut ring, mut data) = {
            let Self { ring, data, .. } = self;
            (ring, data)
        };
        let data_ok = data.release();
        let ring_ok = ring.release();
        data_ok && ring_ok
    }
}

struct Endpoints {
    control: u32,
    provision: u32,
}

fn endpoints(name: &[u8]) -> Endpoints {
    let mut binding_name = [0u8; 48];
    let mut resolve = |suffix: &[u8]| {
        binding_name[..name.len()].copy_from_slice(name);
        binding_name[name.len()..name.len() + suffix.len()].copy_from_slice(suffix);
        binding(&binding_name[..name.len() + suffix.len()])
    };
    Endpoints {
        control: resolve(SUFFIXES[0]),
        provision: resolve(SUFFIXES[1]),
    }
}

fn say(holder: &[u8], what: &[u8]) {
    Line::<128>::new()
        .bytes(b"[zenoh-service] holder ")
        .bytes(what)
        .bytes(b" holder=")
        .bytes(holder)
        .bytes(b"\n")
        .emit();
}

fn reply(answer: &Answer, control: u32) {
    if send(control, &answer.completion, &[]) != ERR_SUCCESS {
        fail(b"control reply");
    }
}

pub fn serve<'k>(
    core: &mut Holders<'k>,
    over: &mut OverLink<'k, { crate::PAYLOAD }>,
    server: &mut Server<{ crate::HOLDERS }>,
    link: &mut Link<'_, '_>,
    handle: slime_components::zenoh_link::LinkHandle,
    clock: &TickClock,
    names: &Names,
) {
    let mut ends: [Option<Endpoints>; crate::HOLDERS] = core::array::from_fn(|_| None);
    let mut sessions: [Option<Session>; crate::HOLDERS] = core::array::from_fn(|_| None);
    let mut attached = 0usize;
    let mut detached = 0usize;
    for (index, end) in ends.iter_mut().enumerate().take(names.count) {
        *end = Some(endpoints(&names.bytes[index][..names.lens[index]]));
    }
    let base = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
    let mut epoch = 1u64;
    while attached == 0 || detached < attached {
        let ticks = monotonic_read().unwrap_or_else(|_| fail(b"clock read"));
        let now = clock.millis(ticks.saturating_sub(base));
        let _ = link.pump(handle, now as u64);
        let _ = core.drain_notices(link);
        let _ = over.settle(core, link).map(|settled| matches!(settled, Settled::Idle));
        while over.declare_next(core, link, handle).unwrap_or(false) {
            let _ = link.pump(handle, now as u64);
            let _ = over.settle(core, link);
        }
        for index in 0..names.count {
            let Some(end) = ends[index].as_ref() else { continue };
            let name = &names.bytes[index][..names.lens[index]];
            let mut bytes = [0u8; MAX_MSG];
            let mut caps = [0u64; MAX_CAPS_PER_MSG];
            match recv(end.control, &mut bytes, &mut caps) {
                ERR_WOULDBLOCK => {}
                count if count == REQUEST_BYTES as i64 => {
                    let request = WireServiceRequest::decode(&bytes[..REQUEST_BYTES]);
                    let op = request.map_or(0, |request| request.op);
                    let answer = control(
                        core,
                        server,
                        &mut sessions[index],
                        index,
                        end.provision,
                        &bytes[..REQUEST_BYTES],
                        &mut epoch,
                        &mut attached,
                        name,
                    );
                    reply(&answer, end.control);
                    if i64::from(op) == wire::OP_DETACH || i64::from(op) == wire::OP_ABORT {
                        if let Some(session) = sessions[index].take()
                            && !session.close()
                        {
                            fail(b"session release");
                        }
                        ends[index] = None;
                        detached += 1;
                        say(name, b"detached");
                    }
                }
                count if count < 0 => fail(b"control receive"),
                _ => reply(&denied(0), end.control),
            }
            if let Some(session) = sessions[index].as_mut() {
                drive(core, over, server, link, handle, index, session, now);
            }
        }
        yield_now();
    }
}

#[allow(clippy::too_many_arguments)]
fn control(
    core: &Holders<'_>,
    server: &mut Server<{ crate::HOLDERS }>,
    session: &mut Option<Session>,
    index: usize,
    provision: u32,
    bytes: &[u8],
    epoch: &mut u64,
    attached: &mut usize,
    name: &[u8],
) -> Answer {
    let answer = server.control(core, index, bytes);
    let op = i64::from(WireServiceRequest::decode(bytes).map_or(0, |request| request.op));
    let status = WireServiceCompletion::decode(&answer.completion).map_or(-1, |completion| completion.status);
    if op == wire::OP_ATTACH && status == 0 {
        *epoch += 1;
        match Session::open(index, provision, *epoch) {
            Ok(opened) => {
                *session = Some(opened);
                *attached += 1;
                let rows = core.row_count(index);
                Line::<128>::new()
                    .bytes(b"[zenoh-service] holder attached holder=")
                    .bytes(name)
                    .bytes(b" rows=")
                    .decimal(rows as u64)
                    .bytes(b"\n")
                    .emit();
            }
            Err(()) => return denied(op as u8),
        }
    }
    answer
}

/// Takes one request from the holder's ring, if there is one, and completes it.
#[allow(clippy::too_many_arguments)]
fn drive<'k>(
    core: &mut Holders<'k>,
    over: &mut OverLink<'k, { crate::PAYLOAD }>,
    server: &mut Server<{ crate::HOLDERS }>,
    link: &mut Link<'_, '_>,
    handle: slime_components::zenoh_link::LinkHandle,
    index: usize,
    session: &mut Session,
    now: i64,
) {
    if session.queue.completions_pending() >= QUEUE_SLOTS as u64 {
        return;
    }
    let mut bytes = [0; REQUEST_PAYLOAD_BYTES];
    let submission = match session.queue.take_request(&mut bytes, DATA_BYTES as u64) {
        Ok(submission) => submission,
        Err(error) if error.error == QueueError::Empty => return,
        Err(_) => fail(b"malformed submission"),
    };
    if !slime_proto::admit_network_request_id(
        &mut session.last_request,
        submission.request_id,
        submission.epoch,
        session.queue.epoch(),
    ) || session
        .outstanding
        .admit(submission.request_id, submission.slice.lease, submission.slice.length)
        .is_err()
        || session.outstanding.start(submission.request_id).is_err()
    {
        fail(b"request admission");
    }
    let length = submission.slice.length as usize;
    let page = unsafe { core::slice::from_raw_parts_mut(session.data.base as *mut u8, DATA_BYTES) };
    let payload_len = if submission.slice.direction == io_queue::DIRECTION_DEVICE_READ {
        length.min(crate::PAYLOAD + 1)
    } else {
        0
    };
    let mut payload = [0u8; crate::PAYLOAD + 1];
    payload[..payload_len].copy_from_slice(&page[..payload_len]);
    let take_room = if submission.slice.direction == io_queue::DIRECTION_DEVICE_WRITE {
        length
    } else {
        0
    };
    let answer = server.request(
        core,
        over,
        link,
        handle,
        index,
        &bytes[..submission.payload_len],
        &payload[..payload_len],
        &mut page[..take_room],
        now,
        now as u64,
    );
    // A refusal is a status in the completion the client reads. The queue's own status is for the queue.
    let status = io_queue::STATUS_OK;
    let transferred = if submission.slice.direction == io_queue::DIRECTION_DEVICE_READ {
        length as u64
    } else {
        answer.page_len as u64
    };
    if session
        .queue
        .complete(submission.request_id, status, transferred, &answer.completion, false)
        .is_err()
        || session.outstanding.settle(submission.request_id, status).is_err()
    {
        fail(b"completion");
    }
}
