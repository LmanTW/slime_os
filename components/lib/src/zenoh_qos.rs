//! The QoS exam: the priority, congestion control and express a Profile 0 PUSH carries.
//!
//! The encoder writes the network QoS extension as eclipse-zenoh 1.0.0 does, and the decoder keeps its
//! value. This module prints one `[zenoh-exam] qos ...` line for each scenario, frame, decoded value and
//! refusal. `scripts/check/check-zenoh-profile0.py --slice qos` owns what those lines must be, and
//! `scripts/lib/zenoh_qos_exam.py` the bytes, the values and the classes.

use crate::zenoh_profile0::encode::FrameEncoder;
use crate::zenoh_profile0::{Mapping, Message, Network, Qos, decode_batch};
use std::vec::Vec;

const FIRST_SN: u32 = 9000;
const KEY: &str = "0/slime_demo/counter/slime_demo_msgs::msg::dds_::Counter_/RIHS01_a82fd5ffcb96d0a197a5ad3680d1c4e6ba43a962928ecd592fb565eb8129595b";
const GID: [u8; 16] = [
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
];
const PAYLOAD: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// (name, priority, block, express): each priority at drop and not express, then each flag alone and together.
const CASES: [(&str, u8, bool, bool); 12] = [
    ("priority-0", 0, false, false),
    ("priority-1", 1, false, false),
    ("priority-2", 2, false, false),
    ("priority-3", 3, false, false),
    ("priority-4", 4, false, false),
    ("priority-5", 5, false, false),
    ("priority-6", 6, false, false),
    ("priority-7", 7, false, false),
    ("block-at-5", 5, true, false),
    ("express-at-5", 5, false, true),
    ("block-express-at-0", 0, true, true),
    ("block-express-at-7", 7, true, true),
];

fn line(kind: &str, text: &str) {
    println!("[zenoh-exam] qos {kind} {text}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn attachment() -> [u8; 33] {
    crate::zenoh_profile0::encode::attachment(1, 1000, &GID).expect("attachment")
}

/// A FRAME of sequence number `sn` holding one PUSH with `qos`, or with the encoder's default when `qos` is `None`.
fn frame(sn: u32, qos: Option<Qos>) -> Vec<u8> {
    let mut out = [0u8; 512];
    let mut frame = FrameEncoder::new(&mut out, sn).expect("frame");
    let attachment = attachment();
    match qos {
        Some(qos) => frame.push_put_qos(Mapping::Sender, KEY, qos, &attachment, &PAYLOAD),
        None => frame.push_put(Mapping::Sender, KEY, &attachment, &PAYLOAD),
    }
    .expect("push");
    let length = frame.finish().expect("finish");
    out[..length].to_vec()
}

fn qos_of(case: (&str, u8, bool, bool)) -> Qos {
    Qos::new(case.1, case.2, case.3).expect("a priority of 0 to 7")
}

/// What a decoded FRAME of one PUSH states.
fn decoded(batch: &[u8]) -> Qos {
    let Ok(Message::Frame(frame)) = decode_batch(batch) else {
        panic!("not a frame");
    };
    let mut messages = frame.messages();
    let Some(Network::PushPut { qos, .. }) = messages.next() else {
        panic!("not a push");
    };
    assert!(messages.next().is_none());
    qos
}

/// The frame of `block-at-5`'s shape with the two bytes of its extension replaced by `extension`, which
/// the decoder reads where the extension stands.
fn with_extension(extension: [u8; 2]) -> Vec<u8> {
    let mut batch = frame(FIRST_SN, Some(Qos::new(0, true, false).expect("qos")));
    // Header, sequence number (two bytes at 9000), PUSH header, scope, key length (two bytes), key.
    let at = 1 + 2 + 1 + 1 + 2 + KEY.len();
    assert_eq!(
        batch[at], 0x21,
        "the extension is where the exam expects it"
    );
    batch[at..at + 2].copy_from_slice(&extension);
    batch
}

#[test]
fn the_qos_exam() {
    // One: the encoder writes the layout the host reference writes, byte for byte.
    let mut frames = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let batch = frame(FIRST_SN + index as u32, Some(qos_of(*case)));
        line("frame", &format!("{} {}", case.0, hex(&batch)));
        frames.push(batch);
    }
    line("ok", "encode-writes-the-upstream-layout");

    // Two: the PUSH default is priority 5, drop, not express. It writes no extension, and the encoder that
    // states no QoS writes the same bytes. Every other value costs the two bytes of the extension.
    let default = frame(FIRST_SN + 5, None);
    assert_eq!(default, frames[5]);
    assert_eq!(Qos::default(), qos_of(CASES[5]));
    for (index, batch) in frames.iter().enumerate() {
        let expected = if index == 5 {
            default.len()
        } else {
            default.len() + 2
        };
        assert_eq!(batch.len(), expected, "{}", CASES[index].0);
    }
    line("ok", "default-qos-writes-no-extension");

    // Three: the decoder keeps the value it reads.
    for (batch, case) in frames.iter().zip(CASES) {
        let qos = decoded(batch);
        assert_eq!(qos, qos_of(case), "{}", case.0);
        line(
            "decoded",
            &format!(
                "{} {} {} {}",
                case.0,
                qos.priority(),
                u8::from(qos.block()),
                u8::from(qos.express())
            ),
        );
    }
    line("ok", "decode-keeps-the-qos-value");

    // Four: every priority comes back as the one that was written, through the default flags.
    for priority in 0..=7u8 {
        let batch = frame(
            FIRST_SN,
            Some(Qos::new(priority, false, false).expect("qos")),
        );
        assert_eq!(decoded(&batch).priority(), priority);
    }
    assert!(Qos::new(8, false, false).is_none());
    line("ok", "every-priority-round-trips");

    // The decoder refuses an extension that is not the optional network QoS, and a value over 0x1F.
    for (name, class, extension) in [
        ("value-over-0x1f", "malformed-message", [0x21, 0x20]),
        (
            "qos-marked-mandatory",
            "unsupported-extension",
            [0x31, 0x08],
        ),
        (
            "extension-other-than-qos",
            "unsupported-extension",
            [0x22, 0x08],
        ),
    ] {
        let batch = with_extension(extension);
        let Err(refusal) = decode_batch(&batch) else {
            panic!("{name} was taken");
        };
        assert_eq!(refusal.name(), class, "{name}");
        line("refused", &format!("{name} {class} {}", hex(&batch)));
    }
}
