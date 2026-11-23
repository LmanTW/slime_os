//! Cross-check of the Zenoh Profile 0 codec and session against the real eclipse-zenoh 1.0.0
//! crates (`zenoh-codec`, `zenoh-protocol`, `zenoh-buffers`).
//!
//! Each part is reported on its own, and every result is also printed as one `[zenoh-xcheck]`
//! line that `scripts/check/check-zenoh-profile0.py --slice xcheck` judges against numbers it
//! pins itself:
//!
//! * A: upstream encodes the accepted corpus batches; the bytes must equal the corpus.
//! * B: a seeded sweep of random messages. Our encoder must equal upstream's byte for byte,
//!   our decoder must read what upstream encodes, and upstream must read what ours encodes and
//!   re-encode it identically. Cases Profile 0 declines are counted by reason, not compared.
//! * C: one session through our state machine; each batch is read and re-encoded by upstream.
//! * E: Zenoh ID edge cases. Upstream holds an ID as a little-endian integer, so it refuses zero
//!   and drops trailing zero bytes; Profile 0 refuses such an ID so that every ID it accepts
//!   round-trips.
//! * D: how many hand-derived refusals upstream also rejects. Informational: upstream accepts
//!   much that Profile 0 refuses on purpose.

use std::time::Duration;

use slime_components::zenoh_profile0::encode as ours;
use slime_components::zenoh_profile0::session::{Config, Event, Role, Session, State};
use slime_components::zenoh_profile0::{
    Mapping as OurMapping, Message, Network, Qos, decode_batch,
};

use zenoh_buffers::{ZBuf, ZSlice, reader::HasReader, writer::HasWriter};
use zenoh_codec::{RCodec, WCodec, Zenoh080};
use zenoh_protocol::{
    core::{Encoding, Reliability, WireExpr, ZenohIdProto},
    network::{
        Mapping, NetworkBody, NetworkMessage,
        declare::{
            self, Declare, DeclareBody, DeclareSubscriber, UndeclareSubscriber,
            common::ext::WireExprType,
        },
        push::Push,
    },
    transport::{
        Frame, TransportBody, TransportMessage, batch_size, close::Close, frame, init::InitAck,
        init::InitSyn, open::OpenAck, open::OpenSyn,
    },
    zenoh::{PushBody, Put},
};

const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

static SESSION_BATCHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PROFILE_REFUSED: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

fn examples() -> &'static Mutex<Vec<String>> {
    static E: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Default)]
struct Tally {
    checked: usize,
    failed: Vec<String>,
}

impl Tally {
    fn ok(&mut self) {
        self.checked += 1;
    }
    fn bad(&mut self, what: String) {
        self.checked += 1;
        self.failed.push(what);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

// ---------- upstream encode / decode ----------

fn up_encode(message: &TransportMessage) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut writer = buffer.writer();
    Zenoh080::new()
        .write(&mut writer, message)
        .expect("upstream encodes");
    buffer
}

fn up_decode(bytes: &[u8]) -> Result<TransportMessage, String> {
    let buffer = bytes.to_vec();
    let mut reader = buffer.reader();
    let message: TransportMessage = Zenoh080::new()
        .read(&mut reader)
        .map_err(|_| "upstream did not decode".to_string())?;
    use zenoh_buffers::reader::Reader;
    if reader.can_read() {
        return Err("upstream left trailing bytes".to_string());
    }
    Ok(message)
}

fn mapping_up(m: OurMapping) -> Mapping {
    match m {
        OurMapping::Sender => Mapping::Sender,
        OurMapping::Receiver => Mapping::Receiver,
    }
}

fn wire(key: &str, mapping: Mapping) -> WireExpr<'static> {
    WireExpr {
        scope: 0,
        suffix: key.to_string().into(),
        mapping,
    }
}

fn zid(bytes: &[u8]) -> ZenohIdProto {
    ZenohIdProto::try_from(bytes).expect("zid")
}

fn up_init_syn(zid_bytes: &[u8], batch: u16) -> TransportMessage {
    TransportMessage {
        body: TransportBody::InitSyn(InitSyn {
            version: 9,
            whatami: zenoh_protocol::core::WhatAmI::Peer,
            zid: zid(zid_bytes),
            resolution: Default::default(),
            batch_size: batch,
            ext_qos: None,
            ext_qos_link: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
        }),
    }
}

fn up_init_ack(zid_bytes: &[u8], batch: u16, cookie: &[u8]) -> TransportMessage {
    TransportMessage {
        body: TransportBody::InitAck(InitAck {
            version: 9,
            whatami: zenoh_protocol::core::WhatAmI::Peer,
            zid: zid(zid_bytes),
            resolution: Default::default(),
            batch_size: batch,
            cookie: ZSlice::from(cookie.to_vec()),
            ext_qos: None,
            ext_qos_link: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
        }),
    }
}

fn up_open_syn(lease_ms: u64, sn: u32, cookie: &[u8]) -> TransportMessage {
    TransportMessage {
        body: TransportBody::OpenSyn(OpenSyn {
            lease: Duration::from_millis(lease_ms),
            initial_sn: sn,
            cookie: ZSlice::from(cookie.to_vec()),
            ext_qos: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
        }),
    }
}

fn up_open_ack(lease_ms: u64, sn: u32) -> TransportMessage {
    TransportMessage {
        body: TransportBody::OpenAck(OpenAck {
            lease: Duration::from_millis(lease_ms),
            initial_sn: sn,
            ext_qos: None,
            ext_auth: None,
            ext_mlink: None,
            ext_lowlatency: None,
            ext_compression: None,
        }),
    }
}

fn up_close(reason: u8, session: bool) -> TransportMessage {
    TransportMessage {
        body: TransportBody::Close(Close { reason, session }),
    }
}

fn net(body: NetworkBody) -> NetworkMessage {
    NetworkMessage {
        body,
        reliability: Reliability::Reliable,
    }
}

fn up_declare(id: u32, key: &str, mapping: Mapping) -> NetworkMessage {
    net(NetworkBody::Declare(Declare {
        interest_id: None,
        ext_qos: declare::ext::QoSType::DEFAULT,
        ext_tstamp: None,
        ext_nodeid: declare::ext::NodeIdType::DEFAULT,
        body: DeclareBody::DeclareSubscriber(DeclareSubscriber {
            id,
            wire_expr: wire(key, mapping),
        }),
    }))
}

fn up_undeclare(id: u32, key: &str, mapping: Mapping) -> NetworkMessage {
    net(NetworkBody::Declare(Declare {
        interest_id: None,
        ext_qos: declare::ext::QoSType::DEFAULT,
        ext_tstamp: None,
        ext_nodeid: declare::ext::NodeIdType::DEFAULT,
        body: DeclareBody::UndeclareSubscriber(UndeclareSubscriber {
            id,
            ext_wire_expr: WireExprType {
                wire_expr: wire(key, mapping),
            },
        }),
    }))
}

fn up_push(key: &str, mapping: Mapping, attachment: &[u8], payload: &[u8]) -> NetworkMessage {
    use zenoh_protocol::zenoh::put::ext::AttachmentType;
    net(NetworkBody::Push(Push {
        wire_expr: wire(key, mapping),
        ext_qos: zenoh_protocol::network::push::ext::QoSType::DEFAULT,
        ext_tstamp: None,
        ext_nodeid: zenoh_protocol::network::push::ext::NodeIdType::DEFAULT,
        payload: PushBody::Put(Put {
            timestamp: None,
            encoding: Encoding::empty(),
            ext_sinfo: None,
            ext_attachment: Some(AttachmentType {
                buffer: ZBuf::from(attachment.to_vec()),
            }),
            ext_unknown: vec![],
            payload: ZBuf::from(payload.to_vec()),
        }),
    }))
}

fn up_frame(sn: u32, messages: Vec<NetworkMessage>) -> TransportMessage {
    TransportMessage {
        body: TransportBody::Frame(Frame {
            reliability: Reliability::Reliable,
            sn,
            ext_qos: frame::ext::QoSType::DEFAULT,
            payload: messages,
        }),
    }
}

// ---------- what our decoder returned, against what upstream was asked to encode ----------

fn zid_bytes(id: &ZenohIdProto) -> Vec<u8> {
    id.to_le_bytes()[..id.size()].to_vec()
}

fn same_network(ours: &Network<'_>, theirs: &NetworkMessage) -> Result<(), String> {
    match (ours, &theirs.body) {
        (
            Network::DeclareSubscriber { id, mapping, key },
            NetworkBody::Declare(Declare {
                body: DeclareBody::DeclareSubscriber(d),
                ..
            }),
        ) => {
            if *id != d.id
                || mapping_up(*mapping) != d.wire_expr.mapping
                || *key != d.wire_expr.suffix.as_ref()
            {
                return Err("declare differs".into());
            }
        }
        (
            Network::UndeclareSubscriber { id, mapping, key },
            NetworkBody::Declare(Declare {
                body: DeclareBody::UndeclareSubscriber(u),
                ..
            }),
        ) => {
            let wire = &u.ext_wire_expr.wire_expr;
            if *id != u.id || mapping_up(*mapping) != wire.mapping || *key != wire.suffix.as_ref() {
                return Err("undeclare differs".into());
            }
        }
        (
            Network::PushPut {
                mapping,
                key,
                attachment,
                payload,
                ..
            },
            NetworkBody::Push(p),
        ) => {
            let PushBody::Put(put) = &p.payload else {
                return Err("push is not a put".into());
            };
            let theirs_attachment = put
                .ext_attachment
                .as_ref()
                .map(|a| zbuf_bytes(&a.buffer))
                .unwrap_or_default();
            if mapping_up(*mapping) != p.wire_expr.mapping
                || *key != p.wire_expr.suffix.as_ref()
                || attachment.raw != &theirs_attachment[..]
                || *payload != &zbuf_bytes(&put.payload)[..]
            {
                return Err("push differs".into());
            }
            // The decoded metadata is read back from upstream's bytes here, not from our
            // encoder: eight little-endian bytes each, a length byte, then the 16-byte GID.
            let theirs_sequence = theirs_attachment
                .get(..8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(i64::from_le_bytes);
            let theirs_timestamp = theirs_attachment
                .get(8..16)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(i64::from_le_bytes);
            let theirs_gid = theirs_attachment.get(17..33);
            if Some(attachment.sequence) != theirs_sequence
                || Some(attachment.timestamp) != theirs_timestamp
                || Some(attachment.gid) != theirs_gid
            {
                return Err("attachment sequence, timestamp or gid differs".into());
            }
        }
        _ => return Err("message kind differs".into()),
    }
    Ok(())
}

/// Every field our decoder returned must equal the one upstream was asked to encode. A decode
/// that merely succeeds can still return a truncated ID, a shifted cookie or a wrong key.
fn same(ours: &Message<'_>, theirs: &TransportMessage) -> Result<(), String> {
    match (ours, &theirs.body) {
        (
            Message::InitSyn {
                zid,
                batch_size,
                qos,
            },
            TransportBody::InitSyn(u),
        ) => {
            if *zid != &zid_bytes(&u.zid)[..]
                || *batch_size != u.batch_size
                || *qos != u.ext_qos.is_some()
            {
                return Err("init syn differs".into());
            }
        }
        (
            Message::InitAck {
                zid,
                batch_size,
                cookie,
                qos,
            },
            TransportBody::InitAck(u),
        ) => {
            if *zid != &zid_bytes(&u.zid)[..]
                || *batch_size != u.batch_size
                || *cookie != u.cookie.as_slice()
                || *qos != u.ext_qos.is_some()
            {
                return Err("init ack differs".into());
            }
        }
        (
            Message::OpenSyn {
                lease_ms,
                initial_sn,
                cookie,
            },
            TransportBody::OpenSyn(u),
        ) => {
            if u128::from(*lease_ms) != u.lease.as_millis()
                || *initial_sn != u.initial_sn
                || *cookie != u.cookie.as_slice()
            {
                return Err("open syn differs".into());
            }
        }
        (
            Message::OpenAck {
                lease_ms,
                initial_sn,
            },
            TransportBody::OpenAck(u),
        ) => {
            if u128::from(*lease_ms) != u.lease.as_millis() || *initial_sn != u.initial_sn {
                return Err("open ack differs".into());
            }
        }
        (Message::Close { reason, session }, TransportBody::Close(u)) => {
            if *reason != u.reason || *session != u.session {
                return Err("close differs".into());
            }
        }
        (Message::Frame(frame), TransportBody::Frame(u)) => {
            if frame.sn != u.sn {
                return Err("frame sequence number differs".into());
            }
            let ours: Vec<_> = frame.messages().collect();
            if ours.len() != u.payload.len() {
                return Err("frame message count differs".into());
            }
            for (o, t) in ours.iter().zip(u.payload.iter()) {
                same_network(o, t)?;
            }
        }
        _ => return Err("message kind differs".into()),
    }
    Ok(())
}

// ---------- our encode ----------

fn our_batch(
    build: impl FnOnce(&mut [u8]) -> Result<usize, ours::EncodeError>,
) -> Result<Vec<u8>, String> {
    let mut out = [0u8; 512];
    let n = build(&mut out).map_err(|e| format!("ours refused: {e:?}"))?;
    Ok(out[..n].to_vec())
}

// ---------- deterministic generator ----------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn bytes_in(&mut self, lo: u64, hi: u64) -> Vec<u8> {
        let n = self.range(lo, hi) as usize;
        self.bytes(n)
    }
    fn key(&mut self) -> String {
        const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_:";
        loop {
            let mut out = String::new();
            let segments = self.range(1, 6);
            for s in 0..segments {
                if s > 0 {
                    out.push('/');
                }
                for _ in 0..self.range(1, 20) {
                    out.push(ALPHA[self.below(ALPHA.len() as u64) as usize] as char);
                }
            }
            if out.len() <= 129 {
                return out;
            }
        }
    }
}

// ---------- A: the 17 corpus vectors, reproduced from the real upstream encoder ----------

fn corpus() -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/lib/src/zenoh_profile0/vectors.txt"
    ))
    .unwrap();
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                ["batch", name, "ok", hexed, summary] => {
                    Some((name.to_string(), hexed.to_string(), summary.to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

fn field<'a>(parts: &'a [(&'a str, &'a str)], name: &str) -> &'a str {
    parts
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
        .unwrap()
}

fn upstream_from_summary(summary: &str) -> TransportMessage {
    let (head, rest) = summary.split_once(';').unwrap();
    if head == "FRAME" {
        let (sn, messages) = rest.split_once(';').unwrap();
        let sn: u32 = sn.strip_prefix("sn=").unwrap().parse().unwrap();
        let mut list = Vec::new();
        for m in messages.split('|') {
            let (name, body) = m.split_once(':').unwrap();
            let all: Vec<(&str, &str)> = body
                .split(',')
                .filter(|p| !p.is_empty())
                .map(|p| p.split_once('=').unwrap())
                .collect();
            let mapping = if all.iter().any(|(k, v)| *k == "mapping" && *v == "sender") {
                Mapping::Sender
            } else {
                Mapping::Receiver
            };
            match name {
                "DECLARE_SUBSCRIBER" => list.push(up_declare(
                    field(&all, "id").parse().unwrap(),
                    field(&all, "key"),
                    mapping,
                )),
                "UNDECLARE_SUBSCRIBER" => list.push(up_undeclare(
                    field(&all, "id").parse().unwrap(),
                    field(&all, "key"),
                    mapping,
                )),
                "PUSH_PUT" => list.push(up_push(
                    field(&all, "key"),
                    mapping,
                    &unhex(field(&all, "att")),
                    &unhex(field(&all, "payload")),
                )),
                other => panic!("{other}"),
            }
        }
        return up_frame(sn, list);
    }
    let parts: Vec<(&str, &str)> = rest
        .split(';')
        .map(|p| p.split_once('=').unwrap())
        .collect();
    match head {
        "INIT_SYN" => up_init_syn(
            &unhex(field(&parts, "zid")),
            field(&parts, "batch").parse().unwrap(),
        ),
        "INIT_ACK" => up_init_ack(
            &unhex(field(&parts, "zid")),
            field(&parts, "batch").parse().unwrap(),
            &unhex(field(&parts, "cookie")),
        ),
        "OPEN_SYN" => up_open_syn(
            field(&parts, "lease_ms").parse().unwrap(),
            field(&parts, "sn").parse().unwrap(),
            &unhex(field(&parts, "cookie")),
        ),
        "OPEN_ACK" => up_open_ack(
            field(&parts, "lease_ms").parse().unwrap(),
            field(&parts, "sn").parse().unwrap(),
        ),
        "CLOSE" => up_close(
            field(&parts, "reason").parse().unwrap(),
            field(&parts, "session") == "1",
        ),
        other => panic!("{other}"),
    }
}

fn part_a(tally: &mut Tally) {
    for (name, expected_hex, summary) in corpus() {
        let produced = hex(&up_encode(&upstream_from_summary(&summary)));
        println!("[zenoh-xcheck] corpus {name} {produced}");
        if produced == expected_hex {
            tally.ok();
        } else {
            tally.bad(format!(
                "corpus {name}: upstream now encodes {produced}, corpus says {expected_hex}"
            ));
        }
    }
}

// ---------- B: sweep. Same field values through both encoders, then cross-decode ----------

fn sweep(
    tally_enc: &mut Tally,
    tally_dec: &mut Tally,
    tally_up_reads_ours: &mut Tally,
    cases: usize,
) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for case in 0..cases {
        let kind = rng.below(9);
        let (label, up, ours_bytes): (String, TransportMessage, Result<Vec<u8>, String>) =
            match kind {
                0 => {
                    let z = rng.bytes_in(1, 16);
                    let batch = [65535u16, 512, rng.range(1, 65534) as u16][rng.below(3) as usize];
                    (
                        format!("init_syn zid={} batch={batch}", hex(&z)),
                        up_init_syn(&z, batch),
                        our_batch(|o| ours::init_syn(o, &z, batch)),
                    )
                }
                1 => {
                    let z = rng.bytes_in(1, 16);
                    let c = rng.bytes_in(1, 64);
                    let batch = [65535u16, 512, rng.range(1, 65534) as u16][rng.below(3) as usize];
                    (
                        format!("init_ack zid={} batch={batch} cookie={}", hex(&z), hex(&c)),
                        up_init_ack(&z, batch, &c),
                        our_batch(|o| ours::init_ack(o, &z, batch, &c)),
                    )
                }
                2 => {
                    let lease = if rng.below(2) == 0 {
                        rng.range(1, 3_600) * 1000
                    } else {
                        rng.range(1, 200_000)
                    };
                    let sn = rng.next() as u32;
                    let c = rng.bytes_in(1, 64);
                    (
                        format!("open_syn lease={lease} sn={sn} cookie={}", hex(&c)),
                        up_open_syn(lease, sn, &c),
                        our_batch(|o| ours::open_syn(o, lease, sn, &c)),
                    )
                }
                3 => {
                    let lease = if rng.below(2) == 0 {
                        rng.range(1, 3_600) * 1000
                    } else {
                        rng.range(1, 200_000)
                    };
                    let sn = rng.next() as u32;
                    (
                        format!("open_ack lease={lease} sn={sn}"),
                        up_open_ack(lease, sn),
                        our_batch(|o| ours::open_ack(o, lease, sn)),
                    )
                }
                4 => {
                    let reason = rng.below(3) as u8;
                    let session = rng.below(2) == 0;
                    (
                        format!("close reason={reason} session={session}"),
                        up_close(reason, session),
                        our_batch(|o| ours::close(o, reason, session)),
                    )
                }
                5 => {
                    let sn = rng.next() as u32;
                    let id = rng.next() as u32;
                    let key = rng.key();
                    let m = if rng.below(2) == 0 {
                        OurMapping::Sender
                    } else {
                        OurMapping::Receiver
                    };
                    (
                        format!("frame declare sn={sn} id={id} key={key} m={m:?}"),
                        up_frame(sn, vec![up_declare(id, &key, mapping_up(m))]),
                        our_batch(|o| {
                            let mut f = ours::FrameEncoder::new(o, sn)?;
                            f.declare_subscriber(id, m, &key)?;
                            f.finish()
                        }),
                    )
                }
                6 => {
                    let sn = rng.next() as u32;
                    let id = rng.next() as u32;
                    let key = rng.key();
                    let m = if rng.below(2) == 0 {
                        OurMapping::Sender
                    } else {
                        OurMapping::Receiver
                    };
                    (
                        format!("frame undeclare sn={sn} id={id} key={key} m={m:?}"),
                        up_frame(sn, vec![up_undeclare(id, &key, mapping_up(m))]),
                        our_batch(|o| {
                            let mut f = ours::FrameEncoder::new(o, sn)?;
                            f.undeclare_subscriber(id, m, &key)?;
                            f.finish()
                        }),
                    )
                }
                8 => {
                    // Two network messages coalesced into one FRAME: a declaration and a put.
                    let sn = rng.next() as u32;
                    let id = rng.next() as u32;
                    let key = rng.key();
                    let m = if rng.below(2) == 0 {
                        OurMapping::Sender
                    } else {
                        OurMapping::Receiver
                    };
                    let seq = rng.next() as i64;
                    let ts = rng.next() as i64;
                    let gid = rng.bytes(16);
                    let payload = rng.bytes_in(1, 12);
                    let att = ours::attachment(seq, ts, &gid).expect("attachment");
                    (
                        format!("frame declare+push sn={sn} id={id} key={key} m={m:?}"),
                        up_frame(
                            sn,
                            vec![
                                up_declare(id, &key, mapping_up(m)),
                                up_push(&key, mapping_up(m), &att, &payload),
                            ],
                        ),
                        our_batch(|o| {
                            let mut f = ours::FrameEncoder::new(o, sn)?;
                            f.declare_subscriber(id, m, &key)?;
                            f.push_put(m, &key, &att, &payload)?;
                            f.finish()
                        }),
                    )
                }
                _ => {
                    let sn = rng.next() as u32;
                    let key = rng.key();
                    let m = if rng.below(2) == 0 {
                        OurMapping::Sender
                    } else {
                        OurMapping::Receiver
                    };
                    let seq = rng.next() as i64;
                    let ts = rng.next() as i64;
                    let gid = rng.bytes(16);
                    let payload = rng.bytes_in(1, 12);
                    let att = ours::attachment(seq, ts, &gid).expect("attachment");
                    (
                        format!(
                            "frame push sn={sn} key={key} m={m:?} seq={seq} payload={}",
                            hex(&payload)
                        ),
                        up_frame(sn, vec![up_push(&key, mapping_up(m), &att, &payload)]),
                        our_batch(|o| {
                            let mut f = ours::FrameEncoder::new(o, sn)?;
                            f.push_put(m, &key, &att, &payload)?;
                            f.finish()
                        }),
                    )
                }
            };
        let theirs = up_encode(&up);
        // Encoder agreement.
        match &ours_bytes {
            Ok(b) if *b == theirs => tally_enc.ok(),
            Ok(b) => tally_enc.bad(format!(
                "#{case} {label}\n    ours   {}\n    theirs {}",
                hex(b),
                hex(&theirs)
            )),
            // Profile 0 deliberately refuses some things upstream accepts; that is not a
            // disagreement about bytes, so it is counted by reason instead of failing.
            Err(e) => {
                *PROFILE_REFUSED
                    .lock()
                    .unwrap()
                    .entry(e.clone())
                    .or_insert(0) += 1;
                if examples().lock().unwrap().len() < 6 {
                    examples().lock().unwrap().push(format!("{label} -> {e}"));
                }
            }
        }
        // Our decoder reads upstream's bytes.
        match decode_batch(&theirs) {
            Ok(read) => match same(&read, &up) {
                Ok(()) => tally_dec.ok(),
                Err(what) => tally_dec.bad(format!(
                    "#{case} {label}: our decoder read upstream's bytes wrongly: {what}"
                )),
            },
            Err(r) => tally_dec.bad(format!(
                "#{case} {label}: our decoder refuses upstream bytes: {r:?}"
            )),
        }
        // Upstream reads our bytes and re-encodes them identically.
        if let Ok(b) = &ours_bytes {
            match up_decode(b) {
                Ok(m) => {
                    let again = up_encode(&m);
                    if &again == b && m == up {
                        tally_up_reads_ours.ok()
                    } else {
                        tally_up_reads_ours.bad(format!("#{case} {label}: upstream decoded ours but differs (equal-to-intended={}, reencode-equal={})", m == up, &again == b))
                    }
                }
                Err(e) => tally_up_reads_ours.bad(format!("#{case} {label}: {e}")),
            }
        }
    }
}

// ---------- C: a real session through our state machine ----------

/// One endpoint takes a batch it was sent. Receiving must succeed and must emit nothing: a batch
/// written here would never be logged, so upstream would never decode it. Returns whether the
/// endpoint reported the session closed.
fn receive(session: &mut Session, label: &str, batch: &[u8], now_ms: u64) -> bool {
    let mut reply = [0u8; 512];
    let outcome = session
        .on_batch(batch, now_ms, &mut reply)
        .unwrap_or_else(|e| panic!("{label}: the receiving endpoint refused it: {e:?}"));
    assert_eq!(
        outcome.sent, 0,
        "{label}: receiving it emitted a batch that is not logged"
    );
    outcome
        .events
        .iter()
        .any(|event| matches!(event, Event::Closed { .. }))
}

fn part_c(tally: &mut Tally) {
    let cookie: Vec<u8> = (0..32).map(|i| 0xc0 + i as u8).collect();
    let zc = [0xa1u8; 8];
    let zl = [0xb2u8; 8];
    let mut a = Session::new(
        Role::Connector,
        &Config {
            zid: &zc,
            lease_ms: 2000,
            initial_sn: u32::MAX - 1,
            cookie: &[],
        },
    )
    .unwrap();
    let mut b = Session::new(
        Role::Listener,
        &Config {
            zid: &zl,
            lease_ms: 2000,
            initial_sn: 7000,
            cookie: &cookie,
        },
    )
    .unwrap();
    let mut log: Vec<(String, Vec<u8>)> = Vec::new();
    let mut out = [0u8; 512];

    macro_rules! emit {
        ($label:expr, $outcome:expr, $buf:expr) => {{
            let o = $outcome.expect($label);
            let bytes = o.batch(&$buf).to_vec();
            log.push(($label.to_string(), bytes.clone()));
            bytes
        }};
    }

    let init_syn = emit!("INIT_SYN", a.connect(0, &mut out), out);
    let init_ack = {
        let mut o2 = [0u8; 512];
        emit!("INIT_ACK", b.on_batch(&init_syn, 1, &mut o2), o2)
    };
    let open_syn = {
        let mut o2 = [0u8; 512];
        emit!("OPEN_SYN", a.on_batch(&init_ack, 2, &mut o2), o2)
    };
    let open_ack = {
        let mut o2 = [0u8; 512];
        emit!("OPEN_ACK", b.on_batch(&open_syn, 3, &mut o2), o2)
    };
    receive(&mut a, "OPEN_ACK received", &open_ack, 4);

    let declare = {
        let mut o2 = [0u8; 512];
        emit!("DECLARE", b.send_declare_subscriber(1, KEY, &mut o2), o2)
    };
    receive(&mut a, "DECLARE received", &declare, 5);

    let gid: Vec<u8> = (0..16).map(|i| 0xe0 + i as u8).collect();
    for (n, payload) in [
        hex_pay("00010000000000000a000000"),
        hex_pay("000100000100000014000000"),
        hex_pay("00010000020000001e000000"),
        hex_pay("000100000300000028000000"),
    ]
    .iter()
    .enumerate()
    {
        let att = ours::attachment(n as i64, 1000 + n as i64, &gid).unwrap();
        let mut o2 = [0u8; 512];
        let put = emit!(
            format!("PUSH_PUT#{n}").as_str(),
            a.send_put(KEY, &att, payload, &mut o2),
            o2
        );
        receive(&mut b, "PUSH_PUT received", &put, 6 + n as u64);
    }
    let undeclare = {
        let mut o2 = [0u8; 512];
        emit!(
            "UNDECLARE",
            b.send_undeclare_subscriber(1, KEY, &mut o2),
            o2
        )
    };
    receive(&mut a, "UNDECLARE received", &undeclare, 20);
    let close = {
        let mut o2 = [0u8; 512];
        emit!("CLOSE", b.close(0, &mut o2), o2)
    };
    assert!(
        receive(&mut a, "CLOSE received", &close, 21),
        "the connector reports the CLOSE it received"
    );
    assert_eq!(a.state(), State::Closed, "the connector is closed");

    for (label, bytes) in &log {
        match up_decode(bytes) {
            Err(e) => tally.bad(format!("{label}: {e} :: {}", hex(bytes))),
            Ok(m) => {
                let again = up_encode(&m);
                if again == *bytes {
                    tally.ok();
                } else {
                    tally.bad(format!(
                        "{label}: re-encode differs\n    ours   {}\n    theirs {}",
                        hex(bytes),
                        hex(&again)
                    ));
                }
                // Field check on the frames.
                if let TransportBody::Frame(f) = &m.body {
                    let ours_view = decode_batch(bytes).expect("ours decodes ours");
                    if let Message::Frame(of) = ours_view {
                        if of.sn != f.sn {
                            tally.bad(format!(
                                "{label}: sn differs ours={} upstream={}",
                                of.sn, f.sn
                            ));
                        } else {
                            tally.ok();
                        }
                        let ours_msgs: Vec<_> = of.messages().collect();
                        if ours_msgs.len() != f.payload.len() {
                            tally.bad(format!("{label}: message count differs"));
                        } else {
                            tally.ok();
                        }
                        for (o, u) in ours_msgs.iter().zip(f.payload.iter()) {
                            if let (Network::PushPut { .. }, NetworkBody::Push(_)) = (o, &u.body) {
                                match same_network(o, u) {
                                    Ok(()) => tally.ok(),
                                    Err(what) => {
                                        tally.bad(format!("{label}: push fields differ: {what}"))
                                    }
                                }
                            }
                        }
                    }
                }
                // Every message kind, not only a PUSH: the pairing above skips a message whose
                // kind differs, so the whole batch is compared once more. Agreement adds no case
                // to the count; a difference is reported.
                match decode_batch(bytes) {
                    Ok(read) => {
                        if let Err(what) = same(&read, &m) {
                            tally.bad(format!("{label}: our decoder read it wrongly: {what}"));
                        }
                    }
                    Err(refusal) => tally.bad(format!(
                        "{label}: our decoder refuses our own batch: {refusal:?}"
                    )),
                }
            }
        }
    }
    SESSION_BATCHES.store(log.len(), std::sync::atomic::Ordering::Relaxed);
    println!(
        "   session drove {} batches: {}",
        log.len(),
        log.iter()
            .map(|(l, b)| format!("{l}({}B)", b.len()))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

fn zbuf_bytes(z: &ZBuf) -> Vec<u8> {
    z.zslices().flat_map(|s| s.as_slice().to_vec()).collect()
}

fn hex_pay(h: &str) -> Vec<u8> {
    unhex(h)
}

// ---------- D: what upstream makes of the hand-derived 'refused' corpus ----------

fn part_d() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/lib/src/zenoh_profile0/vectors.txt"
    ))
    .unwrap();
    let mut agree = 0;
    let mut upstream_accepts: Vec<String> = Vec::new();
    let mut total = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if let ["batch", name, "refused", class, hexed] = f.as_slice() {
            total += 1;
            let bytes = if *hexed == "-" { vec![] } else { unhex(hexed) };
            match up_decode(&bytes) {
                Err(_) => agree += 1,
                Ok(_) => upstream_accepts.push(format!("{name} ({class})")),
            }
        }
    }
    println!(
        "   of {total} hand-derived refused batches, upstream also rejects {agree}; upstream accepts {}:",
        upstream_accepts.len()
    );
    for a in upstream_accepts {
        println!("      - {a}");
    }
}

// ---------- E: Zenoh ID edge cases (upstream stores the ID as a 128-bit LE integer) ----------

fn part_e() {
    println!("E  Zenoh ID edge cases");
    let probes: Vec<(&str, Vec<u8>)> = vec![
        ("all-zero 8B", vec![0; 8]),
        ("all-zero 1B", vec![0]),
        ("trailing zero 8B", vec![1, 2, 3, 4, 5, 6, 7, 0]),
        ("trailing zeros 8B", vec![1, 2, 3, 4, 5, 0, 0, 0]),
        ("leading zero 8B", vec![0, 2, 3, 4, 5, 6, 7, 8]),
        ("interior zero 8B", vec![1, 2, 0, 4, 5, 6, 7, 8]),
        ("canonical 8B", vec![0xa1; 8]),
        ("canonical 16B", vec![0x5a; 16]),
    ];
    for (name, z) in probes {
        let upstream = match ZenohIdProto::try_from(&z[..]) {
            Ok(id) => format!("accepts, wire length {}", id.size()),
            Err(_) => "REFUSES".to_string(),
        };
        let mut out = [0u8; 512];
        let ours_enc = match ours::init_syn(&mut out, &z, 512) {
            Ok(n) => format!("encodes, wire length {} ({n}B)", (out[2] >> 4) + 1),
            Err(e) => format!("refuses ({e:?})"),
        };
        // The other direction: a wire INIT_SYN carrying exactly these bytes.
        let mut wire = vec![0x41u8, 0x09, ((z.len() as u8 - 1) << 4) | 1];
        wire.extend_from_slice(&z);
        wire.extend_from_slice(&[0x0a, 0x00, 0x02]);
        let up_reads = if up_decode(&wire).is_ok() {
            "accepts"
        } else {
            "refuses"
        };
        let our_reads = match decode_batch(&wire) {
            Ok(Message::InitSyn {
                zid,
                batch_size,
                qos: false,
            }) if zid == &z[..] && batch_size == 512 => "accepts",
            Ok(_) => "misreads",
            Err(_) => "refuses",
        };
        println!(
            "[zenoh-xcheck] zid {} upstream={} encode={} wire-upstream={} wire-ours={}",
            hex(&z),
            if upstream.starts_with("REFUSES") {
                "refuses"
            } else {
                "accepts"
            },
            if ours_enc.starts_with("refuses") {
                "refuses"
            } else {
                "encodes"
            },
            up_reads,
            our_reads,
        );
        println!(
            "   {name:18} upstream ID: {upstream:26} | ours encode: {ours_enc:30} | wire INIT_SYN: upstream {up_reads:8} ours {our_reads}"
        );
    }
}

fn report(title: &str, t: &Tally) {
    let verdict = if t.failed.is_empty() { "PASS" } else { "FAIL" };
    println!(
        "{verdict}  {title}: {} checked, {} differ",
        t.checked,
        t.failed.len()
    );
    for f in t.failed.iter().take(8) {
        println!("      {f}");
    }
    if t.failed.len() > 8 {
        println!("      ... and {} more", t.failed.len() - 8);
    }
}

fn main() {
    let cases: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(6000);
    println!(
        "zenoh-codec/zenoh-protocol/zenoh-buffers =1.0.0 vs slime_components::zenoh_profile0 (batch-size default={})",
        batch_size::UNICAST
    );

    let mut a = Tally::default();
    part_a(&mut a);
    report(
        "A  corpus: upstream encoder reproduces the 17 'ok' vectors byte for byte",
        &a,
    );

    let (mut enc, mut dec, mut upr) = (Tally::default(), Tally::default(), Tally::default());
    sweep(&mut enc, &mut dec, &mut upr, cases);
    report(
        &format!("B1 sweep ({cases} cases): our encoder == upstream encoder, byte for byte"),
        &enc,
    );
    {
        let refused = PROFILE_REFUSED.lock().unwrap();
        let total: usize = refused.values().sum();
        println!("   profile-refused (ours declines, upstream encodes): {total} of {cases}");
        for (reason, n) in refused.iter() {
            println!("      {n:5}  {reason}");
        }
        for e in examples().lock().unwrap().iter() {
            println!("      e.g. {e}");
        }
    }
    report(
        "B2 sweep: our decoder accepts everything upstream encodes",
        &dec,
    );
    report(
        "B3 sweep: upstream decodes our bytes to the intended message and re-encodes them identically",
        &upr,
    );

    let mut c = Tally::default();
    println!("C  full session through our state machine");
    part_c(&mut c);
    report(
        "C  every batch our session emits is read and re-encoded identically by upstream",
        &c,
    );

    part_e();

    println!(
        "[zenoh-xcheck] encoder cases={cases} compared={} differ={} refused={}",
        enc.checked,
        enc.failed.len(),
        PROFILE_REFUSED.lock().unwrap().values().sum::<usize>()
    );
    for (reason, n) in PROFILE_REFUSED.lock().unwrap().iter() {
        println!(
            "[zenoh-xcheck] refusal {} {n}",
            reason.trim_start_matches("ours refused: ")
        );
    }
    println!(
        "[zenoh-xcheck] decoder cases={} differ={}",
        dec.checked,
        dec.failed.len()
    );
    println!(
        "[zenoh-xcheck] reader compared={} differ={}",
        upr.checked,
        upr.failed.len()
    );
    println!(
        "[zenoh-xcheck] session batches={} checked={} differ={}",
        SESSION_BATCHES.load(std::sync::atomic::Ordering::Relaxed),
        c.checked,
        c.failed.len()
    );

    println!("D  informational: hand-derived refusals vs upstream");
    part_d();

    let any = !(a.failed.is_empty()
        && enc.failed.is_empty()
        && dec.failed.is_empty()
        && upr.failed.is_empty()
        && c.failed.is_empty());
    std::process::exit(if any { 1 } else { 0 });
}

#[cfg(test)]
mod tests {
    use super::*;
    use slime_components::zenoh_profile0::Attachment;

    #[test]
    fn a_decoded_message_must_carry_the_fields_upstream_was_asked_to_encode() {
        let z = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let theirs = up_init_syn(&z, 512);
        let honest = Message::InitSyn {
            zid: &z,
            batch_size: 512,
            qos: false,
        };
        assert_eq!(same(&honest, &theirs), Ok(()));
        let truncated = Message::InitSyn {
            zid: &z[..7],
            batch_size: 512,
            qos: false,
        };
        assert!(same(&truncated, &theirs).is_err(), "a truncated Zenoh ID");
        let reordered = Message::InitSyn {
            zid: &[8, 7, 6, 5, 4, 3, 2, 1],
            batch_size: 512,
            qos: false,
        };
        assert!(same(&reordered, &theirs).is_err(), "a reordered Zenoh ID");
        let resized = Message::InitSyn {
            zid: &z,
            batch_size: 511,
            qos: false,
        };
        assert!(same(&resized, &theirs).is_err(), "a different batch size");
    }

    fn push<'a>(attachment: Attachment<'a>) -> Network<'a> {
        Network::PushPut {
            mapping: OurMapping::Sender,
            key: "a/b",
            qos: Qos::default(),
            attachment,
            payload: &[1, 2, 3],
        }
    }

    #[test]
    fn a_decoded_push_must_carry_the_attachment_metadata_upstream_encoded() {
        let gid = [0xe0u8; 16];
        let raw = ours::attachment(5, 1005, &gid).unwrap();
        let theirs = up_frame(1, vec![up_push("a/b", Mapping::Sender, &raw, &[1, 2, 3])]);
        let honest = Attachment {
            raw: &raw,
            sequence: 5,
            timestamp: 1005,
            gid: &gid,
        };
        let theirs_network = match &theirs.body {
            TransportBody::Frame(f) => f.payload[0].clone(),
            _ => unreachable!(),
        };
        assert_eq!(same_network(&push(honest), &theirs_network), Ok(()));
        let wrong_sequence = Attachment {
            sequence: 6,
            ..honest
        };
        assert!(same_network(&push(wrong_sequence), &theirs_network).is_err());
        let wrong_timestamp = Attachment {
            timestamp: 0,
            ..honest
        };
        assert!(same_network(&push(wrong_timestamp), &theirs_network).is_err());
        let other_gid = [0u8; 16];
        let wrong_gid = Attachment {
            gid: &other_gid,
            ..honest
        };
        assert!(same_network(&push(wrong_gid), &theirs_network).is_err());
    }

    fn listener() -> Session {
        Session::new(
            Role::Listener,
            &Config {
                zid: &[0xb2; 8],
                lease_ms: 2000,
                initial_sn: 7000,
                cookie: b"cookie",
            },
        )
        .unwrap()
    }

    #[test]
    #[should_panic(expected = "emitted a batch that is not logged")]
    fn receiving_a_batch_that_makes_the_endpoint_reply_is_a_failure() {
        let mut init_syn = [0u8; 512];
        let len = ours::init_syn(&mut init_syn, &[0xa1; 8], 512).unwrap();
        receive(&mut listener(), "INIT_SYN received", &init_syn[..len], 1);
    }

    #[test]
    #[should_panic(expected = "the receiving endpoint refused it")]
    fn receiving_a_batch_the_endpoint_refuses_is_a_failure() {
        let mut close = [0u8; 512];
        let len = ours::close(&mut close, 0, true).unwrap();
        receive(&mut listener(), "CLOSE received", &close[..len], 1);
    }

    #[test]
    fn a_decoded_frame_must_carry_the_same_messages() {
        let key = "a/b";
        let theirs = up_frame(7, vec![up_declare(3, key, Mapping::Sender)]);
        let mut batch = [0u8; 512];
        let len = {
            let mut f = ours::FrameEncoder::new(&mut batch, 7).unwrap();
            f.declare_subscriber(3, OurMapping::Sender, key).unwrap();
            f.finish().unwrap()
        };
        let read = decode_batch(&batch[..len]).unwrap();
        assert_eq!(same(&read, &theirs), Ok(()));
        let other = up_frame(7, vec![up_declare(4, key, Mapping::Sender)]);
        assert!(same(&read, &other).is_err(), "a different declaration id");
        let moved = up_frame(8, vec![up_declare(3, key, Mapping::Sender)]);
        assert!(same(&read, &moved).is_err(), "a different sequence number");
    }
}
