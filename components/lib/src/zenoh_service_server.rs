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
    fn a_take_or_a_control_request_with_a_sequence_or_a_row_is_outside_the_protocol() {
        let (mut server, core) = one_holder();
        let with = |op: i64, row: u16, sequence: i64| {
            WireServiceRequest {
                magic: MAGIC,
                version: VERSION,
                op: op as u8,
                flags: 0,
                row,
                reserved: [0; 2],
                sequence,
                reserved2: [0; 12],
            }
            .encode()
        };
        assert_eq!(
            status(&server.control(&core, 0, &with(wire::OP_ATTACH, 0, 7))),
            STATUS_MALFORMED
        );
        assert_eq!(
            status(&server.control(&core, 0, &with(wire::OP_ATTACH, 1, 0))),
            STATUS_MALFORMED
        );
        assert!(!server.attached(0), "a refused attach changes nothing");
        assert_eq!(
            status(&server.control(&core, 0, &with(wire::OP_ATTACH, 0, 0))),
            0
        );
        for op in [wire::OP_DETACH, wire::OP_ABORT] {
            assert_eq!(
                status(&server.control(&core, 0, &with(op, 0, 3))),
                STATUS_MALFORMED
            );
            assert!(server.attached(0), "a refused teardown leaves the session");
        }
        assert_eq!(
            decode(&with(wire::OP_TAKE, 0, 5)).err().map(|a| status(&a)),
            Some(STATUS_MALFORMED)
        );
        assert_eq!(
            decode(&with(wire::OP_TAKE, 2, 0)).err().map(|a| status(&a)),
            Some(STATUS_MALFORMED)
        );
        assert!(decode(&with(wire::OP_TAKE, 0, 0)).is_ok());
        assert!(
            decode(&with(wire::OP_PUBLISH, 3, 9)).is_ok(),
            "a publish names a row and a sequence"
        );
    }

    /// A publication refused because the stream stalled past the link's retry limit is not delivered locally later.
    #[test]
    fn a_publication_refused_on_a_stalled_stream_is_never_delivered_to_the_rings() {
        use crate::zenoh_link::LinkOf;
        use crate::zenoh_profile0::session::{Params, Role};
        use crate::zenoh_service::OverLink;
        use crate::zenoh_service_link::pair::{Far, Io, Pipe, Stalling, cfg};
        use std::cell::RefCell;
        use std::rc::Rc;

        let ab = Rc::new(RefCell::new(Pipe::default()));
        let ba = Rc::new(RefCell::new(Pipe::default()));
        let stall = Rc::new(RefCell::new(false));
        let params = crate::zenoh_service::exam::params();
        let peer_params = Params {
            local: 2,
            per_side: 3,
            ..params
        };
        let mut svc: LinkOf<Stalling, 514, 1, 5, 129, 12, 8, 4> = LinkOf::with_params(
            Stalling {
                inner: Io {
                    rx: ab.clone(),
                    tx: ba.clone(),
                },
                stall: stall.clone(),
            },
            Role::Listener,
            &cfg(&[0xb2; 8], &[0xc0; 32], 7000),
            params,
            1,
        )
        .expect("service");
        let mut far = Far::with_params(
            Io { rx: ba, tx: ab },
            Role::Connector,
            &cfg(&[0xa1; 8], b"", 9000),
            peer_params,
            1,
        )
        .expect("peer");
        let (hs, hf) = (svc.handle(), far.handle());
        far.open(hf, 0).expect("open");
        for t in 1..=12u64 {
            far.pump(hf, t).expect("pump far");
            svc.pump(hs, t).expect("pump svc");
            if far.is_open() && svc.is_open() {
                break;
            }
        }
        assert!(far.is_open() && svc.is_open());

        let rows = [
            Row {
                holder: 0,
                key: "0/a/b",
                publish: true,
                subscribe: false,
            },
            Row {
                holder: 1,
                key: "0/a/b",
                publish: false,
                subscribe: true,
            },
        ];
        let mut core: Core<'static, 2, 2, 12, 2> =
            Core::new(&rows, [0; 16], &params).expect("grants");
        let mut over = OverLink::<12>::new();
        // The core declares its one subscription, and the peer declares the key so the publication is sent.
        let mut t = 20u64;
        assert!(over.declare_next(&mut core, &mut svc, hs).expect("queues"));
        for _ in 0..3 {
            t += 1;
            far.pump(hf, t).expect("pump far");
            svc.pump(hs, t).expect("pump svc");
        }
        over.settle(&mut core, &svc)
            .expect("settle the declaration");
        far.declare_subscriber(hf, 1, "0/a/b")
            .expect("the peer declares");
        for _ in 0..3 {
            t += 1;
            far.pump(hf, t).expect("pump far");
            svc.pump(hs, t).expect("pump svc");
        }
        while svc.next_notice().is_some() {}

        let mut server = Server::<2>::new();
        assert_eq!(
            status(&server.control(&core, 0, &request(wire::OP_ATTACH))),
            0
        );
        assert_eq!(
            status(&server.control(&core, 1, &request(wire::OP_ATTACH))),
            0
        );
        let publish = WireServiceRequest {
            magic: MAGIC,
            version: VERSION,
            op: wire::OP_PUBLISH as u8,
            flags: 0,
            row: 0,
            reserved: [0; 2],
            sequence: 7,
            reserved2: [0; 12],
        }
        .encode();

        *stall.borrow_mut() = true;
        t += 1;
        let mut page = [0u8; 64];
        let answer = server.request(
            &mut core,
            &mut over,
            &mut svc,
            hs,
            0,
            &publish,
            &[1, 2, 3],
            &mut page,
            100,
            t,
        );
        assert_eq!(status(&answer), STATUS_LINK_CLOSED);
        assert!(svc.is_closed());
        *stall.borrow_mut() = false;
        for _ in 0..4 {
            t += 1;
            let _ = svc.pump(hs, t);
            let _ = over.settle(&mut core, &svc);
        }
        assert_eq!(
            core.held(1).unwrap(),
            (0, 0),
            "a refused publication is not delivered"
        );
    }

    #[test]
    fn the_exchange_lines_name_what_a_request_did() {
        let req = |op: i64, row: u16, sequence: i64| {
            WireServiceRequest {
                magic: MAGIC,
                version: VERSION,
                op: op as u8,
                flags: 0,
                row,
                reserved: [0; 2],
                sequence,
                reserved2: [0; 12],
            }
            .encode()
        };
        let text = |line: Option<crate::zenoh_node::Line<160>>| {
            line.map(|l| String::from_utf8(l.finish().to_vec()).unwrap())
        };
        let published = completion(wire::OP_PUBLISH as u8, 0, wire::ITEM_NONE as u8, 1, 2, 0);
        assert_eq!(
            text(exchange_line(
                b"alpha",
                &req(wire::OP_PUBLISH, 1, 3),
                &published,
                &[]
            ))
            .as_deref(),
            Some("[zenoh-service] published holder=alpha row=1 sequence=3 reached=2 peer=none\n")
        );
        let sent = completion(
            wire::OP_PUBLISH as u8,
            0,
            wire::ITEM_NONE as u8,
            0,
            1,
            wire::FLAG_PEER_SENT as u32,
        );
        assert!(
            text(exchange_line(
                b"alpha",
                &req(wire::OP_PUBLISH, 0, 0),
                &sent,
                &[]
            ))
            .unwrap()
            .ends_with("peer=sent\n")
        );
        let denied_publish = refusal(wire::OP_PUBLISH as u8, STATUS_DENIED, 5);
        assert_eq!(
            text(exchange_line(
                b"beta",
                &req(wire::OP_PUBLISH, 5, 0),
                &denied_publish,
                &[]
            ))
            .as_deref(),
            Some("[zenoh-service] denial class=not-granted holder=beta refused=1\n")
        );
        let too_large = refusal(wire::OP_PUBLISH as u8, STATUS_TOO_LARGE, 0);
        assert!(exchange_line(b"alpha", &req(wire::OP_PUBLISH, 0, 0), &too_large, &[]).is_none());
        let sample = completion(wire::OP_TAKE as u8, 0, wire::ITEM_SAMPLE as u8, 0, 4, 0);
        let mut page = [0u8; HEADER_BYTES + 4];
        page[..8].copy_from_slice(&2i64.to_le_bytes());
        assert_eq!(
            text(exchange_line(
                b"beta",
                &req(wire::OP_TAKE, 0, 0),
                &sample,
                &page
            ))
            .as_deref(),
            Some("[zenoh-service] delivered holder=beta row=0 sequence=2\n")
        );
        let empty = completion(wire::OP_TAKE as u8, 0, wire::ITEM_NONE as u8, 0, 0, 0);
        assert!(exchange_line(b"beta", &req(wire::OP_TAKE, 0, 0), &empty, &[]).is_none());
        assert!(exchange_line(b"beta", &req(wire::OP_ATTACH, 0, 0), &published, &[]).is_none());
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

/// The console line for what one request did, or none for a request that prints nothing. The lines are the ones the
/// booted exchange is judged on: a publication names its row, its sequence and how many holders it reached, a taken
/// sample names its row and sequence, and a publication refused for a row the holder lacks is a `not-granted` denial.
pub fn exchange_line(
    holder: &[u8],
    request: &[u8],
    answer: &Answer,
    page: &[u8],
) -> Option<crate::zenoh_node::Line<160>> {
    use crate::zenoh_node::Line;
    let request = WireServiceRequest::decode(request)?;
    let done = WireServiceCompletion::decode(&answer.completion)?;
    let mut line = Line::<160>::new();
    if i64::from(request.op) == wire::OP_PUBLISH {
        if done.status == STATUS_DENIED {
            line.put(b"[zenoh-service] denial class=not-granted holder=")
                .put(holder)
                .put(b" refused=1\n");
            return Some(line);
        }
        if done.status != 0 {
            return None;
        }
        let peer: &[u8] = if u64::from(done.flags) & wire::FLAG_PEER_SENT as u64 != 0 {
            b"sent"
        } else {
            b"none"
        };
        line.put(b"[zenoh-service] published holder=")
            .put(holder)
            .put(b" row=")
            .put_number(u64::from(done.row))
            .put(b" sequence=")
            .put_signed(request.sequence)
            .put(b" reached=")
            .put_number(u64::from(done.length))
            .put(b" peer=")
            .put(peer)
            .put(b"\n");
        return Some(line);
    }
    if i64::from(request.op) == wire::OP_TAKE
        && done.status == 0
        && i64::from(done.item) == wire::ITEM_SAMPLE
    {
        let header = WireSampleHeader::decode(page)?;
        line.put(b"[zenoh-service] delivered holder=")
            .put(holder)
            .put(b" row=")
            .put_number(u64::from(done.row))
            .put(b" sequence=")
            .put_signed(header.sequence)
            .put(b"\n");
        return Some(line);
    }
    None
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
    // The schema fixes the sequence at zero for every operation but a publish, and the row at zero for all but a
    // publish. A request that sets either is outside the protocol and changes nothing.
    if i64::from(op) != wire::OP_PUBLISH && (request.sequence != 0 || request.row != 0) {
        return Err(refusal(op, STATUS_MALFORMED, request.row));
    }
    Ok(request)
}
