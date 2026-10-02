//! Host tests for the Zenoh Profile 0 encoder.
//!
//! Each accepted corpus batch is rebuilt from the values its summary names and
//! compared with the bytes the upstream encoder produced. The `[zenoh-exam]`
//! lines are what `scripts/check/check-zenoh-profile0.py --slice encoder` reads.

use super::*;
use crate::zenoh_profile0::{Message, Network, decode_batch};
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

const VECTORS: &str = include_str!("vectors.txt");

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length in {text}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write");
    }
    out
}

/// `(name, hex, summary)` of every accepted batch in the corpus.
fn corpus() -> Vec<(&'static str, &'static str, &'static str)> {
    VECTORS
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["batch", name, "ok", hexed, summary] => Some((*name, *hexed, *summary)),
                _ => None,
            }
        })
        .collect()
}

fn fields(text: &str) -> Vec<(&str, &str)> {
    text.split(',')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').expect("field"))
        .collect()
}

fn field<'a>(all: &[(&'a str, &'a str)], name: &str) -> &'a str {
    all.iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn mapping_of(all: &[(&str, &str)]) -> Mapping {
    match all.iter().find(|(key, _)| *key == "mapping") {
        Some((_, "sender")) => Mapping::Sender,
        _ => Mapping::Receiver,
    }
}

fn frame_message(frame: &mut FrameEncoder<'_>, text: &str) -> Result<(), EncodeError> {
    let (name, rest) = text.split_once(':').expect("network message");
    let all = fields(rest);
    let mapping = mapping_of(&all);
    match name {
        "DECLARE_SUBSCRIBER" => {
            let id = field(&all, "id").parse().expect("id");
            frame.declare_subscriber(id, mapping, field(&all, "key"))
        }
        "UNDECLARE_SUBSCRIBER" => {
            let id = field(&all, "id").parse().expect("id");
            frame.undeclare_subscriber(id, mapping, field(&all, "key"))
        }
        "PUSH_PUT" => {
            let raw = unhex(field(&all, "att"));
            let rebuilt = attachment(
                i64::from_le_bytes(raw[0..8].try_into().expect("sequence")),
                i64::from_le_bytes(raw[8..16].try_into().expect("timestamp")),
                &raw[17..],
            )
            .expect("attachment");
            assert_eq!(rebuilt.as_slice(), raw.as_slice(), "attachment builder");
            frame.push_put(
                mapping,
                field(&all, "key"),
                &rebuilt,
                &unhex(field(&all, "payload")),
            )
        }
        other => panic!("unknown network message {other}"),
    }
}

/// Encodes the batch a corpus summary describes, from the values it names.
fn encode_summary(summary: &str, out: &mut [u8]) -> Result<usize, EncodeError> {
    let (head, rest) = summary.split_once(';').expect("summary head");
    if head == "FRAME" {
        let (sn, messages) = rest.split_once(';').expect("frame body");
        let sn = sn.strip_prefix("sn=").expect("sn").parse().expect("sn");
        let mut frame = FrameEncoder::new(out, sn)?;
        for message in messages.split('|') {
            frame_message(&mut frame, message)?;
        }
        return frame.finish();
    }
    let parts: Vec<(&str, &str)> = rest
        .split(';')
        .map(|part| part.split_once('=').expect("field"))
        .collect();
    let zid = || unhex(field(&parts, "zid"));
    let cookie = || unhex(field(&parts, "cookie"));
    match head {
        "INIT_SYN" => init_syn(out, &zid(), field(&parts, "batch").parse().expect("batch")),
        "INIT_ACK" => init_ack(
            out,
            &zid(),
            field(&parts, "batch").parse().expect("batch"),
            &cookie(),
        ),
        "OPEN_SYN" => open_syn(
            out,
            field(&parts, "lease_ms").parse().expect("lease"),
            field(&parts, "sn").parse().expect("sn"),
            &cookie(),
        ),
        "OPEN_ACK" => open_ack(
            out,
            field(&parts, "lease_ms").parse().expect("lease"),
            field(&parts, "sn").parse().expect("sn"),
        ),
        "CLOSE" => close(
            out,
            field(&parts, "reason").parse().expect("reason"),
            field(&parts, "session") == "1",
        ),
        other => panic!("unknown batch {other}"),
    }
}

fn mapping_name(mapping: Mapping) -> &'static str {
    match mapping {
        Mapping::Sender => "sender",
        Mapping::Receiver => "receiver",
    }
}

fn network_summary(message: &Network<'_>) -> String {
    match message {
        Network::DeclareSubscriber { id, mapping, key } => format!(
            "DECLARE_SUBSCRIBER:id={id},mapping={},key={key}",
            mapping_name(*mapping)
        ),
        Network::UndeclareSubscriber { id, mapping, key } => format!(
            "UNDECLARE_SUBSCRIBER:id={id},mapping={},key={key}",
            mapping_name(*mapping)
        ),
        Network::PushPut {
            mapping,
            key,
            attachment,
            payload,
        } => format!(
            "PUSH_PUT:mapping={},key={key},att={},payload={}",
            mapping_name(*mapping),
            hex(attachment.raw),
            hex(payload)
        ),
    }
}

fn decoded_summary(batch: &[u8]) -> String {
    match decode_batch(batch).expect("decoder accepts the encoded batch") {
        Message::InitSyn { zid, batch_size } => {
            format!("INIT_SYN;v=9;zid={};batch={batch_size}", hex(zid))
        }
        Message::InitAck {
            zid,
            batch_size,
            cookie,
        } => format!(
            "INIT_ACK;v=9;zid={};batch={batch_size};cookie={}",
            hex(zid),
            hex(cookie)
        ),
        Message::OpenSyn {
            lease_ms,
            initial_sn,
            cookie,
        } => format!(
            "OPEN_SYN;lease_ms={lease_ms};sn={initial_sn};cookie={}",
            hex(cookie)
        ),
        Message::OpenAck {
            lease_ms,
            initial_sn,
        } => format!("OPEN_ACK;lease_ms={lease_ms};sn={initial_sn}"),
        Message::Close { reason, session } => {
            format!("CLOSE;reason={reason};session={}", u8::from(session))
        }
        Message::Frame(frame) => {
            let parts: Vec<String> = frame.messages().map(|m| network_summary(&m)).collect();
            format!("FRAME;sn={};{}", frame.sn, parts.join("|"))
        }
    }
}

fn refused(control: &str, outcome: Result<usize, EncodeError>, expected: EncodeError) {
    assert_eq!(outcome, Err(expected), "{control}");
    println!("[zenoh-exam] encode refused {control}");
}

const KEY: &str = "0/slime_demo/counter";

fn good_attachment() -> [u8; MAX_ATTACHMENT_BYTES] {
    attachment(1, 1000, &[7; GID_BYTES]).expect("attachment")
}

#[test]
fn corpus_has_seventeen_accepted_batches() {
    assert_eq!(corpus().len(), 17);
}

#[test]
fn encoder_reproduces_every_upstream_batch() {
    for (name, expected, summary) in corpus() {
        let mut out = [0u8; MAX_BATCH_BYTES];
        let length = encode_summary(summary, &mut out).expect(name);
        let produced = hex(&out[..length]);
        assert_eq!(produced, expected, "{name}");
        println!("[zenoh-exam] encode ok {name} {produced}");
    }
}

#[test]
fn encoded_batches_decode_to_the_corpus_summary() {
    for (name, _, summary) in corpus() {
        let mut out = [0u8; MAX_BATCH_BYTES];
        let length = encode_summary(summary, &mut out).expect(name);
        assert_eq!(decoded_summary(&out[..length]), summary, "{name}");
    }
}

#[test]
fn encoder_refuses_what_the_profile_forbids() {
    let mut out = [0u8; 1024];
    let attachment = good_attachment();

    let long_key = "a".repeat(MAX_KEY_BYTES + 1);
    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    refused(
        "key-over-129-bytes",
        frame
            .push_put(Mapping::Sender, &long_key, &attachment, &[])
            .map(|()| 0),
        EncodeError::KeyTooLong,
    );
    assert_eq!(
        frame.declare_subscriber(1, Mapping::Sender, &long_key),
        Err(EncodeError::KeyTooLong)
    );
    assert_eq!(
        frame.undeclare_subscriber(1, Mapping::Sender, &long_key),
        Err(EncodeError::KeyTooLong)
    );
    assert_eq!(frame.finish(), Err(EncodeError::EmptyFrame));

    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    refused(
        "attachment-not-33-bytes",
        frame
            .push_put(Mapping::Sender, KEY, &attachment[..32], &[])
            .map(|()| 0),
        EncodeError::AttachmentLength,
    );
    let mut longer = attachment.to_vec();
    longer.push(0);
    assert_eq!(
        frame.push_put(Mapping::Sender, KEY, &longer, &[]),
        Err(EncodeError::AttachmentLength)
    );

    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    refused(
        "payload-over-12-bytes",
        frame
            .push_put(
                Mapping::Sender,
                KEY,
                &attachment,
                &[0; MAX_PAYLOAD_BYTES + 1],
            )
            .map(|()| 0),
        EncodeError::PayloadTooLong,
    );

    refused(
        "cookie-over-64-bytes",
        open_syn(&mut out, 2000, 0, &[1; MAX_COOKIE_BYTES + 1]),
        EncodeError::CookieTooLong,
    );
    assert_eq!(
        init_ack(&mut out, &[1], 512, &[1; MAX_COOKIE_BYTES + 1]),
        Err(EncodeError::CookieTooLong)
    );
    assert_eq!(
        open_syn(&mut out, 2000, 0, &[]),
        Err(EncodeError::CookieEmpty)
    );
    assert_eq!(
        init_ack(&mut out, &[1], 512, &[]),
        Err(EncodeError::CookieEmpty)
    );
    assert!(open_syn(&mut out, 2000, 0, &[1; MAX_COOKIE_BYTES]).is_ok());

    assert_eq!(init_syn(&mut out, &[], 512), Err(EncodeError::ZidLength));
    refused(
        "zid-empty-or-over-16-bytes",
        init_syn(&mut out, &[1; 17], 512),
        EncodeError::ZidLength,
    );
    assert_eq!(
        init_ack(&mut out, &[], 512, &[1]),
        Err(EncodeError::ZidLength)
    );

    for key in ["0/a/*", "0/**", "0/a/b$*c", "0/a$*/b"] {
        let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
        assert_eq!(
            frame.declare_subscriber(1, Mapping::Sender, key),
            Err(EncodeError::WildcardKey),
            "{key}"
        );
        assert_eq!(
            frame.undeclare_subscriber(1, Mapping::Sender, key),
            Err(EncodeError::WildcardKey),
            "{key}"
        );
        assert_eq!(
            frame.push_put(Mapping::Sender, key, &attachment, &[]),
            Err(EncodeError::WildcardKey),
            "{key}"
        );
    }
    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    refused(
        "wildcard-key",
        frame
            .declare_subscriber(1, Mapping::Sender, "0/slime_demo/*/counter")
            .map(|()| 0),
        EncodeError::WildcardKey,
    );

    let key = "k".repeat(MAX_KEY_BYTES);
    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    let mut outcome = Ok(0);
    for _ in 0..4 {
        outcome = frame
            .push_put(Mapping::Sender, &key, &attachment, &[0; MAX_PAYLOAD_BYTES])
            .map(|()| 0);
        if outcome.is_err() {
            break;
        }
    }
    refused("batch-over-512-bytes", outcome, EncodeError::BatchTooLarge);
}

#[test]
fn failed_message_leaves_the_frame_unchanged() {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let mut frame = FrameEncoder::new(&mut out, 3).expect("frame");
    frame
        .declare_subscriber(1, Mapping::Sender, KEY)
        .expect("declare");
    assert!(
        frame
            .undeclare_subscriber(1, Mapping::Sender, "a/*")
            .is_err()
    );
    let length = frame.finish().expect("finish");
    let mut reference = [0u8; MAX_BATCH_BYTES];
    let mut only = FrameEncoder::new(&mut reference, 3).expect("frame");
    only.declare_subscriber(1, Mapping::Sender, KEY)
        .expect("declare");
    assert_eq!(only.finish(), Ok(length));
    assert_eq!(out[..length], reference[..length]);
}

#[test]
fn small_storage_is_refused_not_truncated() {
    let mut out = [0u8; 4];
    assert_eq!(
        init_syn(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8], u16::MAX),
        Err(EncodeError::OutputTooSmall)
    );
    assert_eq!(
        close(&mut [0u8; 1], 0, true),
        Err(EncodeError::OutputTooSmall)
    );
    assert_eq!(close(&mut [0u8; 2], 0, true), Ok(2));
    assert_eq!(
        FrameEncoder::new(&mut [], 0).err(),
        Some(EncodeError::OutputTooSmall)
    );
    let mut tight = [0u8; 20];
    let mut frame = FrameEncoder::new(&mut tight, 0).expect("frame");
    assert_eq!(
        frame.declare_subscriber(1, Mapping::Sender, KEY),
        Err(EncodeError::OutputTooSmall)
    );
}

#[test]
fn values_the_decoder_refuses_are_not_encoded() {
    let mut out = [0u8; MAX_BATCH_BYTES];
    assert_eq!(init_syn(&mut out, &[1], 0), Err(EncodeError::BatchSizeZero));
    assert_eq!(open_ack(&mut out, 0, 0), Err(EncodeError::LeaseOutOfRange));
    assert_eq!(
        open_ack(&mut out, u64::from(u32::MAX) + 1, 0),
        Err(EncodeError::LeaseOutOfRange)
    );
    assert_eq!(
        close(&mut out, 8, false),
        Err(EncodeError::CloseReasonUnknown)
    );
    let attachment = good_attachment();
    let mut frame = FrameEncoder::new(&mut out, 0).expect("frame");
    for key in ["", "/a", "a/", "a//b", "a?b", "a#b"] {
        assert_eq!(
            frame.declare_subscriber(1, Mapping::Sender, key),
            Err(EncodeError::InvalidKey),
            "{key:?}"
        );
    }
    let mut bad_gid = attachment;
    bad_gid[16] = 15;
    assert_eq!(
        frame.push_put(Mapping::Sender, KEY, &bad_gid, &[]),
        Err(EncodeError::AttachmentGid)
    );
    assert_eq!(
        super::attachment(0, 0, &[0; 15]),
        Err(EncodeError::AttachmentGid)
    );
}

#[test]
fn stream_prefix_is_two_little_endian_bytes() {
    assert_eq!(stream_prefix(2), Ok([2, 0]));
    assert_eq!(stream_prefix(512), Ok([0, 2]));
    assert_eq!(stream_prefix(0), Err(EncodeError::StreamLength));
    assert_eq!(stream_prefix(513), Err(EncodeError::StreamLength));
    let mut out = [0u8; 4];
    assert_eq!(stream_batch(&mut out, &[0x23, 0x00]), Ok(4));
    assert_eq!(out, [2, 0, 0x23, 0]);
    assert_eq!(
        stream_batch(&mut [0u8; 3], &[0x23, 0x00]),
        Err(EncodeError::OutputTooSmall)
    );
}

#[test]
fn stream_framer_reads_back_what_the_encoder_wrote() {
    let mut batch = [0u8; MAX_BATCH_BYTES];
    let length = open_ack(&mut batch, 2000, 9).expect("open ack");
    let mut wire = [0u8; STREAM_LENGTH_BYTES + MAX_BATCH_BYTES];
    let total = stream_batch(&mut wire, &batch[..length]).expect("stream");
    let mut framer = crate::zenoh_profile0::StreamFramer::new();
    assert_eq!(framer.push(&wire[..total]), total);
    assert_eq!(framer.peek_batch(), Ok(Some(&batch[..length])));
}
