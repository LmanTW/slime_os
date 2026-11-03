//! The server half of the Zenoh service client protocol.
//!
//! `zenoh_service_client` is the holder's half. This half takes one request a holder wrote, the payload that travelled
//! with it, and the time, and returns the completion the client checks. It keeps each holder's phase and asks the
//! Zenoh service core for the rest. It owns no ring, no loan, no endpoint and no link, and it makes no runtime call,
//! so a host test drives it with the client protocol's bytes.
//!
//! The holder is the one whose endpoint the request arrived on, never one a request names. A request names a grant
//! row by an index below the holder's own row count, and never a key. A refused request changes no ring and writes
//! nothing to the peer. Every completion echoes the operation, and a publish completion echoes the request's row
//! whatever its status.
//!
//! A publication is queued through the link and completes when the link flushes it. The server pumps the link and
//! settles up to [`PUMP_BOUND`] times. A link that has not flushed by then leaves the publication waiting, and the
//! holder is told the link is closed, because the protocol has no answer for a publication in flight.

#[cfg(test)]
mod exam;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zenoh_service::{Core, Row};

    /// The server exam: the server answers each request of the client protocol and the test prints one
    /// `[zenoh-exam] server ...` line for each answer. The checker looks for this test by its path.
    #[test]
    fn the_server_exam() {
        super::exam::run();
    }

    fn request(op: i64) -> [u8; REQUEST_BYTES] {
        WireServiceRequest {
            magic: MAGIC,
            version: VERSION,
            op: op as u8,
            flags: 0,
            row: 0,
            reserved: [0; 2],
            sequence: 0,
            reserved2: [0; 12],
        }
        .encode()
    }

    fn one_holder() -> (Server<1>, Core<'static, 1, 1, 12, 1>) {
        let rows = [Row {
            holder: 0,
            key: "0/a/b",
            publish: true,
            subscribe: true,
        }];
        let core =
            Core::new(&rows, [0; 16], &crate::zenoh_service::exam::params()).expect("grants");
        (Server::new(), core)
    }

    fn status(answer: &Answer) -> i32 {
        WireServiceCompletion::decode(&answer.completion)
            .expect("a completion")
            .status
    }

    #[test]
    fn a_request_longer_than_the_wire_request_is_not_a_request() {
        let (mut server, core) = one_holder();
        let mut longer = [0u8; REQUEST_BYTES + 8];
        longer[..REQUEST_BYTES].copy_from_slice(&request(wire::OP_ATTACH));
        assert_eq!(status(&server.control(&core, 0, &longer)), STATUS_MALFORMED);
        assert!(!server.attached(0), "a refused request changes nothing");
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            0
        );
        assert!(server.attached(0));
        assert_eq!(
            status(&server.control(&core, 0, &longer[..REQUEST_BYTES - 1])),
            STATUS_MALFORMED
        );
    }

    #[test]
    fn a_holder_the_host_could_not_provision_may_attach_again() {
        let (mut server, core) = one_holder();
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            0
        );
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            STATUS_DENIED
        );
        server.unattach(0);
        assert!(!server.attached(0));
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            0
        );
        // A holder that never attached, or already ended, is not moved.
        server.unattach(5);
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_DETACH))),
            0
        );
        server.unattach(0);
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            STATUS_DENIED
        );
    }
}

use crate::zenoh_link::{ByteLink, LinkHandle, LinkOf};
use crate::zenoh_service::{Core, Item, OverLink, ServiceError, Settled};
use slime_proto::zenoh_service_client as wire;
use slime_proto::zenoh_service_client_wire::{
    COMPLETION_LEN, REQUEST_LEN, SAMPLE_HEADER_LEN, WireSampleHeader, WireServiceCompletion,
    WireServiceRequest,
};

const MAGIC: u32 = wire::SERVICE_MAGIC as u32;
const VERSION: u16 = wire::FORMAT_VERSION as u16;
/// The bytes in front of a sample's payload in the data page.
pub const HEADER_BYTES: usize = SAMPLE_HEADER_LEN;
pub const REQUEST_BYTES: usize = REQUEST_LEN;
pub const COMPLETION_BYTES: usize = COMPLETION_LEN;
/// How many times a publication pumps the link and settles before the holder is told the link is closed.
pub const PUMP_BOUND: usize = 8;

const STATUS_DENIED: i32 = wire::STATUS_DENIED as i32;
const STATUS_MALFORMED: i32 = wire::STATUS_MALFORMED as i32;
const STATUS_UNSUPPORTED: i32 = wire::STATUS_UNSUPPORTED as i32;
const STATUS_TOO_LARGE: i32 = wire::STATUS_TOO_LARGE as i32;
const STATUS_LINK_CLOSED: i32 = wire::STATUS_LINK_CLOSED as i32;

/// What a holder's session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No session. The holder may attach.
    Idle,
    /// The holder attached and has not detached or aborted.
    Attached,
    /// The holder detached or aborted. Nothing more is served to it.
    Ended,
}

/// What the server answers: a completion, and how many bytes of the data page it wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub completion: [u8; COMPLETION_BYTES],
    /// The bytes written to the data page, which is zero except for a sample.
    pub page_len: usize,
}

fn status_of(error: ServiceError) -> i32 {
    match error {
        ServiceError::NotGranted | ServiceError::UnknownHolder => STATUS_DENIED,
        ServiceError::TooLarge => STATUS_TOO_LARGE,
        ServiceError::Busy | ServiceError::Session(_) | ServiceError::Link(_) => STATUS_LINK_CLOSED,
        ServiceError::InvalidGrants | ServiceError::WrongSession => STATUS_DENIED,
    }
}

fn completion(op: u8, status: i32, item: u8, row: u16, length: u32, flags: u32) -> Answer {
    Answer {
        completion: WireServiceCompletion {
            magic: MAGIC,
            version: VERSION,
            op,
            item,
            status,
            row,
            reserved: [0; 2],
            length,
            flags,
        }
        .encode(),
        page_len: 0,
    }
}

fn refusal(op: u8, status: i32, row: u16) -> Answer {
    completion(op, status, wire::ITEM_NONE as u8, row, 0, 0)
}

/// The completion the server answers a request of operation `op` with when the host cannot serve it, such as an
/// attach that found no buffers. It carries only a denied status, as every refusal does.
pub fn denied(op: u8) -> Answer {
    refusal(op, STATUS_DENIED, 0)
}

/// The server over `H` holders. It keeps each holder's phase and nothing of the core's.
pub struct Server<const H: usize> {
    phases: [Phase; H],
}

impl<const H: usize> Server<H> {
    pub const fn new() -> Self {
        Self {
            phases: [Phase::Idle; H],
        }
    }

    /// Whether `holder` has a session.
    pub fn attached(&self, holder: usize) -> bool {
        self.phases.get(holder) == Some(&Phase::Attached)
    }

    /// Puts `holder` back to having no session. The host calls it when it could not give an attached holder its
    /// buffers, so the holder may attach again and is not left counted as attached.
    pub fn unattach(&mut self, holder: usize) {
        if let Some(phase) = self.phases.get_mut(holder)
            && *phase == Phase::Attached
        {
            *phase = Phase::Idle;
        }
    }

    /// Answers the control request `bytes`, which arrived on `holder`'s endpoint. Attach, detach and abort travel
    /// here. A request of another operation is answered as the operation it names, and changes nothing.
    pub fn control<'k, const N: usize, const P: usize, const R: usize>(
        &mut self,
        core: &Core<'k, H, N, P, R>,
        holder: usize,
        bytes: &[u8],
    ) -> Answer {
        let request = match decode(bytes) {
            Ok(request) => request,
            Err(answer) => return answer,
        };
        let op = request.op;
        let Some(phase) = self.phases.get_mut(holder) else {
            return refusal(op, STATUS_DENIED, 0);
        };
        match i64::from(op) {
            wire::OP_ATTACH => {
                let count = core.row_count(holder);
                if *phase != Phase::Idle || count == 0 {
                    return refusal(op, STATUS_DENIED, 0);
                }
                *phase = Phase::Attached;
                completion(op, 0, wire::ITEM_NONE as u8, 0, count as u32, 0)
            }
            wire::OP_DETACH | wire::OP_ABORT => {
                if *phase != Phase::Attached {
                    return refusal(op, STATUS_DENIED, 0);
                }
                *phase = Phase::Ended;
                completion(op, 0, wire::ITEM_NONE as u8, 0, 0, 0)
            }
            _ => refusal(op, STATUS_UNSUPPORTED, 0),
        }
    }

    /// Answers a publish or a take that arrived in `holder`'s ring. `payload` is what the holder wrote to the data
    /// page for a publish. `page` is the data page a take's sample is written to. `now` is the service's clock, which
    /// stamps every publication, and `tick_ms` is the time the link is pumped at.
    #[allow(clippy::too_many_arguments)]
    pub fn request<
        'k,
        const N: usize,
        const P: usize,
        const R: usize,
        L: ByteLink,
        const F: usize,
        const K: usize,
        const S: usize,
        const B: usize,
        const QQ: usize,
        const E: usize,
    >(
        &mut self,
        core: &mut Core<'k, H, N, P, R>,
        over: &mut OverLink<'k, P>,
        link: &mut LinkOf<L, F, K, S, B, P, QQ, E>,
        handle: LinkHandle,
        holder: usize,
        bytes: &[u8],
        payload: &[u8],
        page: &mut [u8],
        now: i64,
        tick_ms: u64,
    ) -> Answer {
        let request = match decode(bytes) {
            Ok(request) => request,
            Err(answer) => return answer,
        };
        let op = request.op;
        let row = request.row;
        if !self.attached(holder) {
            return refusal(op, STATUS_DENIED, row);
        }
        match i64::from(op) {
            wire::OP_PUBLISH => {
                let Some((key, may_publish)) = core.row_key(holder, usize::from(row)) else {
                    return refusal(op, STATUS_MALFORMED, row);
                };
                if !may_publish {
                    return refusal(op, STATUS_DENIED, row);
                }
                publish(
                    core, over, link, handle, holder, key, row, &request, payload, now, tick_ms,
                )
            }
            wire::OP_TAKE => take(core, holder, page),
            _ => refusal(op, STATUS_UNSUPPORTED, 0),
        }
    }
}

impl<const H: usize> Default for Server<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Queues the publication, then pumps the link and settles until it leaves or the bound is spent.
#[allow(clippy::too_many_arguments)]
fn publish<
    'k,
    const H: usize,
    const N: usize,
    const P: usize,
    const R: usize,
    L: ByteLink,
    const F: usize,
    const K: usize,
    const S: usize,
    const B: usize,
    const QQ: usize,
    const E: usize,
>(
    core: &mut Core<'k, H, N, P, R>,
    over: &mut OverLink<'k, P>,
    link: &mut LinkOf<L, F, K, S, B, P, QQ, E>,
    handle: LinkHandle,
    holder: usize,
    key: &'k str,
    row: u16,
    request: &WireServiceRequest,
    payload: &[u8],
    now: i64,
    tick_ms: u64,
) -> Answer {
    let op = request.op;
    match over.publish(
        core,
        link,
        handle,
        holder,
        key,
        request.sequence,
        now,
        payload,
    ) {
        // The peer declared nothing on the key. The local copies were delivered at once.
        Ok(Some(published)) => completion(
            op,
            0,
            wire::ITEM_NONE as u8,
            row,
            published.reached as u32,
            0,
        ),
        Ok(None) => {
            for _ in 0..PUMP_BOUND {
                if link.pump(handle, tick_ms).is_err() {
                    return refusal(op, STATUS_LINK_CLOSED, row);
                }
                match over.settle(core, link) {
                    Ok(Settled::Published { reached }) => {
                        return completion(
                            op,
                            0,
                            wire::ITEM_NONE as u8,
                            row,
                            reached as u32,
                            wire::FLAG_PEER_SENT as u32,
                        );
                    }
                    Ok(Settled::Waiting) => {}
                    Ok(_) | Err(_) => return refusal(op, STATUS_LINK_CLOSED, row),
                }
            }
            refusal(op, STATUS_LINK_CLOSED, row)
        }
        Err(error) => refusal(op, status_of(error), row),
    }
}

/// The holder's next item. A sample is written to the data page after its header. A buffer too small for the next
/// sample leaves it in the ring.
fn take<'k, const H: usize, const N: usize, const P: usize, const R: usize>(
    core: &mut Core<'k, H, N, P, R>,
    holder: usize,
    page: &mut [u8],
) -> Answer {
    let op = wire::OP_TAKE as u8;
    match core.peek(holder) {
        Ok(None) => completion(op, 0, wire::ITEM_NONE as u8, 0, 0, 0),
        Ok(Some(Item::Lost { count })) => {
            let _ = core.take(holder);
            completion(op, 0, wire::ITEM_LOSS as u8, 0, count, 0)
        }
        Ok(Some(Item::Sample(sample))) => {
            let need = HEADER_BYTES + sample.payload().len();
            if page.len() < need {
                return refusal(op, STATUS_TOO_LARGE, 0);
            }
            let Some(row) = core.row_of(holder, sample.subscription) else {
                return refusal(op, STATUS_DENIED, 0);
            };
            let _ = core.take(holder);
            let header = WireSampleHeader {
                sequence: sample.sequence,
                timestamp: sample.timestamp,
            }
            .encode();
            page[..HEADER_BYTES].copy_from_slice(&header);
            page[HEADER_BYTES..need].copy_from_slice(sample.payload());
            let mut answer = completion(
                op,
                0,
                wire::ITEM_SAMPLE as u8,
                u16::try_from(row).unwrap_or(0),
                sample.payload().len() as u32,
                0,
            );
            answer.page_len = need;
            answer
        }
        Err(error) => refusal(op, status_of(error), 0),
    }
}

/// Reads a request, or answers the one the bytes are: a request outside the protocol is answered with the operation
/// it names, and changes nothing.
fn decode(bytes: &[u8]) -> Result<WireServiceRequest, Answer> {
    // The wire request is exactly `REQUEST_BYTES`. A longer slice is not a request, whatever its prefix says.
    let Some(request) = WireServiceRequest::decode(bytes).filter(|_| bytes.len() == REQUEST_BYTES)
    else {
        return Err(refusal(0, STATUS_MALFORMED, 0));
    };
    let op = request.op;
    if request.magic != MAGIC
        || request.version != VERSION
        || request.reserved != [0; 2]
        || request.reserved2 != [0; 12]
        || request.flags != 0
    {
        return Err(refusal(op, STATUS_MALFORMED, request.row));
    }
    if !(wire::OP_ATTACH..=wire::OP_ABORT).contains(&i64::from(op)) {
        return Err(refusal(op, STATUS_UNSUPPORTED, request.row));
    }
    Ok(request)
}
