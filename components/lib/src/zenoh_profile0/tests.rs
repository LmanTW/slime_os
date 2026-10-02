//! Host tests for the Zenoh Profile 0 codec.
//!
//! `vectors.txt` is the conformance corpus: accepted batches produced by the
//! upstream eclipse-zenoh 1.0.0 encoder, refused inputs derived from the
//! profile's rules, and stream reassembly cases. A decoded message is compared
//! through a summary string so each vector states its expectation in the file.

use super::*;
use std::fmt::Write as _;
use std::vec::Vec;

const VECTORS: &str = include_str!("vectors.txt");

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
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

fn mapping(mapping: Mapping) -> &'static str {
    match mapping {
        Mapping::Sender => "sender",
        Mapping::Receiver => "receiver",
    }
}

fn network_summary(message: &Network<'_>) -> String {
    match message {
        Network::DeclareSubscriber {
            id,
            mapping: m,
            key,
        } => {
            format!(
                "DECLARE_SUBSCRIBER:id={id},mapping={},key={key}",
                mapping(*m)
            )
        }
        Network::UndeclareSubscriber {
            id,
            mapping: m,
            key,
        } => {
            format!(
                "UNDECLARE_SUBSCRIBER:id={id},mapping={},key={key}",
                mapping(*m)
            )
        }
        Network::PushPut {
            mapping: m,
            key,
            attachment,
            payload,
        } => format!(
            "PUSH_PUT:mapping={},key={key},att={},payload={}",
            mapping(*m),
            hex(attachment.raw),
            hex(payload)
        ),
    }
}

fn summary(message: &Message<'_>) -> String {
    match message {
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
            format!("CLOSE;reason={reason};session={}", u8::from(*session))
        }
        Message::Frame(frame) => {
            let parts: Vec<String> = frame.messages().map(|m| network_summary(&m)).collect();
            format!("FRAME;sn={};{}", frame.sn, parts.join("|"))
        }
    }
}

fn verdict(batch: &[u8]) -> String {
    match decode_batch(batch) {
        Ok(message) => format!("ok {}", summary(&message)),
        Err(refusal) => format!("refused {}", refusal.name()),
    }
}

/// Feeds `chunks` through a framer the way a caller would and reports what it
/// yields, in the vector file's terms.
fn stream_verdict(chunks: &[Vec<u8>]) -> String {
    let mut framer = StreamFramer::new();
    let mut batches: Vec<String> = Vec::new();
    for chunk in chunks {
        let mut rest = chunk.as_slice();
        loop {
            let taken = framer.push(rest);
            rest = &rest[taken..];
            loop {
                match framer.peek_batch() {
                    Err(refusal) => return format!("refused {}", refusal.name()),
                    Ok(None) => break,
                    Ok(Some(batch)) => batches.push(hex(batch)),
                }
                framer.consume_batch();
            }
            if rest.is_empty() {
                break;
            }
        }
    }
    let joined = if batches.is_empty() {
        "-".to_string()
    } else {
        batches.join(",")
    };
    format!("ok {joined} {}", framer.pending())
}

struct Vector<'a> {
    kind: &'a str,
    name: &'a str,
    request: &'a str,
    expected: String,
}

fn vectors() -> Vec<Vector<'static>> {
    let mut out = Vec::new();
    for (index, raw) in VECTORS.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        let at = index + 1;
        let vector = match (f[0], f[2], f.len()) {
            ("batch", "ok", 5) => Vector {
                kind: "batch",
                name: f[1],
                request: f[3],
                expected: format!("ok {}", f[4]),
            },
            ("batch", "refused", 5) | ("stream", "refused", 5) => Vector {
                kind: if f[0] == "batch" { "batch" } else { "stream" },
                name: f[1],
                request: f[4],
                expected: format!("refused {}", f[3]),
            },
            ("stream", "ok", 6) => Vector {
                kind: "stream",
                name: f[1],
                request: f[3],
                expected: format!("ok {} {}", f[4], f[5]),
            },
            _ => panic!("vectors.txt:{at}: malformed line: {line}"),
        };
        out.push(vector);
    }
    out
}

fn chunks(request: &str) -> Vec<Vec<u8>> {
    request.split(',').map(unhex).collect()
}

fn run(vector: &Vector<'_>) -> String {
    match vector.kind {
        "batch" => verdict(&unhex(vector.request)),
        _ => stream_verdict(&chunks(vector.request)),
    }
}

#[test]
fn corpus_agrees() {
    let all = vectors();
    assert_eq!(all.len(), 129, "the corpus changed size");
    let mut wrong = Vec::new();
    for vector in &all {
        let got = run(vector);
        if got != vector.expected {
            wrong.push(format!(
                "{} {}: wants {:?}, got {got:?}",
                vector.kind, vector.name, vector.expected
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_refusal_class_is_drawn() {
    let all = vectors();
    for code in 1..=p::REFUSAL_CLASS_COUNT as u8 {
        let name = p::refusal_name(code).expect("a class per code");
        let wanted = format!("refused {name}");
        assert!(
            all.iter().any(|vector| vector.expected == wanted),
            "no vector draws {name}"
        );
    }
    assert_eq!(
        p::refusal_name(0),
        None,
        "zero is reserved for accepted input"
    );
    assert_eq!(p::refusal_name(p::REFUSAL_CLASS_COUNT as u8 + 1), None);
}

#[test]
fn refusal_codes_and_names_round_trip() {
    let every = [
        Refusal::EmptyBatch,
        Refusal::LengthExceedsBatch,
        Refusal::Truncated,
        Refusal::TrailingBytes,
        Refusal::UnsupportedVersion,
        Refusal::UnsupportedWhatami,
        Refusal::UnsupportedResolution,
        Refusal::UnsupportedExtension,
        Refusal::UnsupportedMessage,
        Refusal::MalformedMessage,
        Refusal::OverBound,
        Refusal::Leb128Overflow,
        Refusal::Leb128Noncanonical,
        Refusal::WildcardKeyexpr,
        Refusal::InvalidKeyexpr,
    ];
    assert_eq!(every.len(), p::REFUSAL_CLASS_COUNT);
    for (index, refusal) in every.iter().enumerate() {
        assert_eq!(usize::from(refusal.code()), index + 1);
        assert_ne!(refusal.name(), "unknown");
    }
}

#[test]
fn bounds_equal_the_frozen_demo_contract() {
    let fixture = include_str!("../../../../contracts/rpi5-ros2-demo/v2/fixtures/valid.zti");
    let field = |name: &str| -> usize {
        let needle = format!("{name} = ");
        let at = fixture
            .find(&needle)
            .unwrap_or_else(|| panic!("fixture lacks {name}"));
        fixture[at + needle.len()..]
            .split(';')
            .next()
            .expect("value")
            .trim()
            .parse()
            .expect("integer")
    };
    assert_eq!(field("maxTransportMessageBytes"), MAX_BATCH_BYTES);
    assert_eq!(field("maxKeyexprBytes"), MAX_KEY_BYTES);
    assert_eq!(field("maxAttachmentBytes"), MAX_ATTACHMENT_BYTES);
    assert_eq!(field("maxPayloadBytes"), MAX_PAYLOAD_BYTES);
    assert_eq!(field("protocolVersion") as u32, p::PROTOCOL_VERSION);
    assert_eq!(field("batchLengthBytes"), STREAM_LENGTH_BYTES);
    assert_eq!(MAX_ATTACHMENT_BYTES, 8 + 8 + 1 + GID_BYTES);
}

/// A batch the profile accepts, cut short at every length. Network messages in a
/// FRAME are self-delimiting, so a prefix that ends on a message boundary is a
/// valid shorter frame; any other prefix must be refused. Nothing may panic.
#[test]
fn every_prefix_of_every_accepted_batch_is_refused_or_a_shorter_frame() {
    let mut refused = 0usize;
    let mut shorter_frames = 0usize;
    for vector in vectors()
        .iter()
        .filter(|v| v.kind == "batch" && v.expected.starts_with("ok "))
    {
        let bytes = unhex(vector.request);
        let full_messages = match decode_batch(&bytes) {
            Ok(Message::Frame(frame)) => Some(frame.messages().count()),
            _ => None,
        };
        for length in 0..bytes.len() {
            match decode_batch(&bytes[..length]) {
                Err(_) => refused += 1,
                Ok(Message::Frame(frame)) => {
                    let total = full_messages.unwrap_or_else(|| {
                        panic!(
                            "{}: a non-frame decoded a {length}-byte prefix",
                            vector.name
                        )
                    });
                    assert!(
                        frame.messages().count() < total,
                        "{}: a {length}-byte prefix decoded as many messages as the whole",
                        vector.name
                    );
                    shorter_frames += 1;
                }
                Ok(_) => panic!("{}: a {length}-byte prefix decoded", vector.name),
            }
        }
    }
    assert!(refused > 0);
    // Exactly one: the coalesced DECLARE + PUSH frame cut after its DECLARE.
    assert_eq!(shorter_frames, 1);
}

/// Single-bit damage never panics, and a decode that survives is still bounded.
#[test]
fn byte_flips_never_panic_and_stay_bounded() {
    for vector in vectors()
        .iter()
        .filter(|v| v.kind == "batch" && v.expected.starts_with("ok "))
    {
        let bytes = unhex(vector.request);
        for position in 0..bytes.len() {
            for flip in [0x01u8, 0x80] {
                let mut mutated = bytes.clone();
                mutated[position] ^= flip;
                if let Ok(Message::Frame(frame)) = decode_batch(&mutated) {
                    for message in frame.messages() {
                        match message {
                            Network::DeclareSubscriber { key, .. }
                            | Network::UndeclareSubscriber { key, .. } => {
                                assert!(key.len() <= MAX_KEY_BYTES);
                            }
                            Network::PushPut {
                                key,
                                attachment,
                                payload,
                                ..
                            } => {
                                assert!(key.len() <= MAX_KEY_BYTES);
                                assert_eq!(attachment.raw.len(), MAX_ATTACHMENT_BYTES);
                                assert_eq!(attachment.gid.len(), GID_BYTES);
                                assert!(payload.len() <= MAX_PAYLOAD_BYTES);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Every two-way split of a framed batch reassembles to the same batch.
#[test]
fn every_two_chunk_split_reassembles() {
    for vector in vectors()
        .iter()
        .filter(|v| v.kind == "batch" && v.expected.starts_with("ok "))
    {
        let batch = unhex(vector.request);
        let mut framed = (batch.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(&batch);
        for cut in 1..framed.len() {
            let got = stream_verdict(&[framed[..cut].to_vec(), framed[cut..].to_vec()]);
            assert_eq!(
                got,
                format!("ok {} 0", hex(&batch)),
                "{} split at {cut}",
                vector.name
            );
        }
    }
}

#[test]
fn decoded_values_borrow_from_the_batch() {
    let batch = unhex(
        vectors()
            .iter()
            .find(|v| v.name == "frame_push_put_sn1")
            .expect("vector")
            .request,
    );
    let Ok(Message::Frame(frame)) = decode_batch(&batch) else {
        panic!("not a frame");
    };
    let Some(Network::PushPut {
        attachment,
        payload,
        key,
        ..
    }) = frame.messages().next()
    else {
        panic!("not a push");
    };
    let range = batch.as_ptr_range();
    for slice in [attachment.raw, payload, key.as_bytes()] {
        assert!(
            range.contains(&slice.as_ptr()),
            "value was copied out of the batch"
        );
    }
    assert_eq!(attachment.sequence, 1);
    assert_eq!(attachment.timestamp, 1000);
    assert_eq!(attachment.gid.len(), GID_BYTES);
    assert_eq!(payload, &unhex("000100000100000014000000")[..]);
}

#[test]
fn framer_holds_a_maximum_batch_and_refuses_the_next_byte_of_overflow() {
    let mut framer = StreamFramer::new();
    let mut wire = (MAX_BATCH_BYTES as u16).to_le_bytes().to_vec();
    wire.extend(std::iter::repeat_n(0u8, MAX_BATCH_BYTES));
    assert_eq!(framer.push(&wire), wire.len());
    assert_eq!(framer.pending(), STREAM_LENGTH_BYTES + MAX_BATCH_BYTES);
    // Full: another byte is not taken until a batch is consumed.
    assert_eq!(framer.push(&[0xAA]), 0);
    assert!(framer.peek_batch().expect("no refusal").is_some());
    framer.consume_batch();
    assert_eq!(framer.pending(), 0);
    assert_eq!(framer.push(&[0xAA]), 1);
}

#[test]
fn framer_refuses_a_bad_prefix_before_the_body_arrives() {
    let mut framer = StreamFramer::new();
    framer.push(&[0x01, 0x02]);
    assert_eq!(framer.peek_batch(), Err(Refusal::LengthExceedsBatch));
    let mut framer = StreamFramer::new();
    framer.push(&[0x00, 0x00]);
    assert_eq!(framer.peek_batch(), Err(Refusal::EmptyBatch));
}

/// The decoder is a pure function of its input: no state survives a refusal.
#[test]
fn a_refusal_does_not_poison_the_next_decode() {
    let good = unhex("2300");
    assert!(decode_batch(&good).is_ok());
    assert!(decode_batch(&[0xFF]).is_err());
    assert_eq!(verdict(&good), "ok CLOSE;reason=0;session=1");
}
