//! Host tests for the `Counter` classic-CDR codec, judged against the demo
//! contract fixture's four samples.

use super::*;
use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;

const FIXTURE: &str = include_str!("../../../../contracts/rpi5-ros2-demo/v2/fixtures/valid.zti");

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write");
    }
    out
}

fn field<'a>(block: &'a str, name: &str) -> &'a str {
    let needle = format!("{name} = ");
    let at = block
        .find(&needle)
        .unwrap_or_else(|| panic!("sample lacks {name}"));
    block[at + needle.len()..]
        .split(';')
        .next()
        .expect("value")
        .trim()
}

/// The fixture's `samples` block as (sequence, value, cdrHex).
fn fixture_samples() -> Vec<(u32, i32, String)> {
    let start = FIXTURE.find("samples = [").expect("samples block");
    let block = &FIXTURE[start..];
    let block = &block[..block.find("];").expect("samples end")];
    block
        .split('{')
        .skip(1)
        .map(|sample| {
            (
                field(sample, "sequence").parse().expect("sequence"),
                field(sample, "value").parse().expect("value"),
                field(sample, "cdrHex").trim_matches('"').to_string(),
            )
        })
        .collect()
}

fn valid() -> [u8; MAX_SERIALIZED_BYTES] {
    let mut out = [0u8; MAX_SERIALIZED_BYTES];
    let written = Counter {
        sequence: 7,
        value: -9,
    }
    .encode(&mut out)
    .expect("encode");
    assert_eq!(written, MAX_SERIALIZED_BYTES);
    out
}

#[test]
fn max_serialized_bytes_equals_the_demo_contract() {
    let field = |name: &str| -> usize {
        let needle = format!("{name} = ");
        let at = FIXTURE
            .find(&needle)
            .unwrap_or_else(|| panic!("fixture lacks {name}"));
        FIXTURE[at + needle.len()..]
            .split(';')
            .next()
            .expect("value")
            .trim()
            .parse()
            .expect("integer")
    };
    assert_eq!(MAX_SERIALIZED_BYTES, 12);
    assert_eq!(field("maxSerializedBytes"), MAX_SERIALIZED_BYTES);
    assert_eq!(field("maxMessageBytes"), MAX_SERIALIZED_BYTES);
    assert_eq!(field("maxPayloadBytes"), MAX_SERIALIZED_BYTES);
}

#[test]
fn fixture_samples_round_trip_byte_for_byte() {
    let samples = fixture_samples();
    assert_eq!(samples.len(), 4);
    for (sequence, value, wanted) in samples {
        let counter = Counter { sequence, value };
        let mut out = [0u8; MAX_SERIALIZED_BYTES];
        let written = counter.encode(&mut out).expect("encode");
        assert_eq!(written, MAX_SERIALIZED_BYTES);
        let produced = hex(&out[..written]);
        assert_eq!(produced, wanted);
        assert_eq!(Counter::decode(&out[..written]), Ok(counter));
        println!("[zenoh-exam] cdr ok {sequence} {value} {produced}");
    }
}

#[test]
fn extreme_values_round_trip() {
    for (sequence, value) in [
        (0, i32::MIN),
        (u32::MAX, i32::MAX),
        (u32::MAX, -1),
        (0x0102_0304, 0x0506_0708),
    ] {
        let counter = Counter { sequence, value };
        let mut out = [0u8; MAX_SERIALIZED_BYTES];
        let written = counter.encode(&mut out).expect("encode");
        assert_eq!(Counter::decode(&out[..written]), Ok(counter));
    }
}

#[test]
fn encode_larger_buffer_writes_only_the_message() {
    let mut out = [0xaa_u8; MAX_SERIALIZED_BYTES + 4];
    let counter = Counter {
        sequence: 1,
        value: 20,
    };
    assert_eq!(counter.encode(&mut out), Ok(MAX_SERIALIZED_BYTES));
    assert_eq!(
        hex(&out[..MAX_SERIALIZED_BYTES]),
        "000100000100000014000000"
    );
    assert_eq!(out[MAX_SERIALIZED_BYTES..], [0xaa; 4]);
}

#[test]
fn encode_into_a_too_small_buffer_is_refused_without_writing() {
    let counter = Counter {
        sequence: 3,
        value: 40,
    };
    for size in 0..MAX_SERIALIZED_BYTES {
        let mut out = [0x5a_u8; MAX_SERIALIZED_BYTES];
        assert_eq!(
            counter.encode(&mut out[..size]),
            Err(CdrError::BufferTooSmall)
        );
        assert_eq!(out, [0x5a; MAX_SERIALIZED_BYTES], "size {size}");
    }
}

#[test]
fn every_prefix_of_a_valid_encoding_is_refused() {
    for (sequence, value, wanted) in fixture_samples() {
        let mut out = [0u8; MAX_SERIALIZED_BYTES];
        Counter { sequence, value }
            .encode(&mut out)
            .expect("encode");
        assert_eq!(hex(&out), wanted);
        for len in 0..MAX_SERIALIZED_BYTES {
            let expected = if len < 4 {
                CdrError::TruncatedHeader
            } else {
                CdrError::TruncatedBody
            };
            assert_eq!(Counter::decode(&out[..len]), Err(expected), "prefix {len}");
        }
    }
}

#[test]
fn every_extension_of_a_valid_encoding_is_refused() {
    let base = valid();
    for extra in 1..=16 {
        let mut input = base.to_vec();
        input.resize(MAX_SERIALIZED_BYTES + extra, 0);
        let expected = if extra <= 3 {
            CdrError::TrailingBytes
        } else {
            CdrError::OverMax
        };
        assert_eq!(Counter::decode(&input), Err(expected), "extra {extra}");
    }
}

#[test]
fn refusals_name_their_own_variant() {
    let base = valid();

    assert_eq!(Counter::decode(&base[..3]), Err(CdrError::TruncatedHeader));
    println!("[zenoh-exam] cdr refused truncated-header");

    assert_eq!(Counter::decode(&base[..11]), Err(CdrError::TruncatedBody));
    println!("[zenoh-exam] cdr refused truncated-body");

    let mut trailing = base.to_vec();
    trailing.push(0);
    assert_eq!(Counter::decode(&trailing), Err(CdrError::TrailingBytes));
    println!("[zenoh-exam] cdr refused trailing-bytes");

    let mut big_endian = base;
    big_endian[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        Counter::decode(&big_endian),
        Err(CdrError::BigEndianEncapsulation)
    );
    println!("[zenoh-exam] cdr refused big-endian-encapsulation");

    for unknown in [[0x00, 0x02], [0x01, 0x01], [0x00, 0x06], [0xff, 0xff]] {
        let mut input = base;
        input[..2].copy_from_slice(&unknown);
        assert_eq!(
            Counter::decode(&input),
            Err(CdrError::UnknownEncapsulation),
            "{unknown:?}"
        );
    }
    println!("[zenoh-exam] cdr refused unknown-encapsulation");

    for options in [[0x00, 0x01], [0x01, 0x00], [0xff, 0xff]] {
        let mut input = base;
        input[2..4].copy_from_slice(&options);
        assert_eq!(
            Counter::decode(&input),
            Err(CdrError::NonzeroOptions),
            "{options:?}"
        );
    }
    println!("[zenoh-exam] cdr refused nonzero-options");

    let mut over = base.to_vec();
    over.resize(64, 0);
    assert_eq!(Counter::decode(&over), Err(CdrError::OverMax));
    println!("[zenoh-exam] cdr refused over-max-serialized");
}

#[test]
fn encapsulation_is_judged_before_the_body() {
    let mut big_endian_short = [0u8; 6];
    big_endian_short[..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        Counter::decode(&big_endian_short),
        Err(CdrError::BigEndianEncapsulation)
    );
    let mut options_short = [0u8; 5];
    options_short[3] = 1;
    options_short[1] = 1;
    assert_eq!(
        Counter::decode(&options_short),
        Err(CdrError::NonzeroOptions)
    );
}

#[test]
fn decode_never_panics_on_short_or_odd_inputs() {
    let pool = [0x00_u8, 0x01, 0x02, 0xff];
    let mut input = Vec::new();
    for seed in 0..4096_u32 {
        input.clear();
        let len = (seed % 17) as usize;
        let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push(pool[(state >> 24) as usize % pool.len()]);
        }
        let _ = Counter::decode(&input);
    }
}
