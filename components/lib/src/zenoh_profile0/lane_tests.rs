//! Host tests for the lane decoder. The header bytes are what `zenoh-codec` 1.0.0 wrote for a `FrameHeader`
//! and a `FragmentHeader`; `scripts/lib/zenoh_lanes_exam.py` holds the same strings.

use super::*;
use std::vec::Vec;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// (reliable, priority, sequence number, header bytes), as the exam's `UPSTREAM_FRAMES` lists them.
const FRAMES: [(bool, u8, u32, &str); 16] = [
    (true, 0, 5, "a5053100"),
    (true, 0, 7000, "a5d8363100"),
    (true, 2, 5, "a5053102"),
    (true, 2, 7000, "a5d8363102"),
    (true, 5, 5, "2505"),
    (true, 5, 7000, "25d836"),
    (true, 7, 5, "a5053107"),
    (true, 7, 7000, "a5d8363107"),
    (false, 0, 5, "85053100"),
    (false, 0, 7000, "85d8363100"),
    (false, 2, 5, "85053102"),
    (false, 2, 7000, "85d8363102"),
    (false, 5, 5, "0505"),
    (false, 5, 7000, "05d836"),
    (false, 7, 5, "85053107"),
    (false, 7, 7000, "85d8363107"),
];

/// (reliable, priority, more, sequence number, header bytes).
const FRAGMENTS: [(bool, u8, bool, u32, &str); 32] = [
    (true, 0, true, 5, "e6053100"),
    (true, 0, true, 300, "e6ac023100"),
    (true, 0, false, 5, "a6053100"),
    (true, 0, false, 300, "a6ac023100"),
    (true, 2, true, 5, "e6053102"),
    (true, 2, true, 300, "e6ac023102"),
    (true, 2, false, 5, "a6053102"),
    (true, 2, false, 300, "a6ac023102"),
    (true, 5, true, 5, "6605"),
    (true, 5, true, 300, "66ac02"),
    (true, 5, false, 5, "2605"),
    (true, 5, false, 300, "26ac02"),
    (true, 7, true, 5, "e6053107"),
    (true, 7, true, 300, "e6ac023107"),
    (true, 7, false, 5, "a6053107"),
    (true, 7, false, 300, "a6ac023107"),
    (false, 0, true, 5, "c6053100"),
    (false, 0, true, 300, "c6ac023100"),
    (false, 0, false, 5, "86053100"),
    (false, 0, false, 300, "86ac023100"),
    (false, 2, true, 5, "c6053102"),
    (false, 2, true, 300, "c6ac023102"),
    (false, 2, false, 5, "86053102"),
    (false, 2, false, 300, "86ac023102"),
    (false, 5, true, 5, "4605"),
    (false, 5, true, 300, "46ac02"),
    (false, 5, false, 5, "0605"),
    (false, 5, false, 300, "06ac02"),
    (false, 7, true, 5, "c6053107"),
    (false, 7, true, 300, "c6ac023107"),
    (false, 7, false, 5, "86053107"),
    (false, 7, false, 300, "86ac023107"),
];

fn with_body(header: &str) -> Vec<u8> {
    let mut bytes = unhex(header);
    bytes.extend_from_slice(&[0xde, 0xad]);
    bytes
}

#[test]
fn every_frame_header_upstream_wrote_is_read_back() {
    for (reliable, priority, sn, header) in FRAMES {
        let bytes = with_body(header);
        let frame = decode_lane_frame(&bytes).expect(header);
        assert_eq!(frame.lane, Lane { priority, reliable }, "{header}");
        assert_eq!(frame.sn, sn, "{header}");
        assert_eq!(frame.body, [0xde, 0xad], "{header}");
    }
}

#[test]
fn every_fragment_header_upstream_wrote_is_read_back() {
    for (reliable, priority, more, sn, header) in FRAGMENTS {
        let bytes = with_body(header);
        let fragment = decode_lane_fragment(&bytes, None).expect(header);
        assert_eq!(fragment.lane, Lane { priority, reliable }, "{header}");
        assert_eq!(fragment.more, more, "{header}");
        assert_eq!(fragment.sn, sn, "{header}");
        assert_eq!(fragment.data, [0xde, 0xad], "{header}");
    }
}

#[test]
fn the_default_priority_has_no_extension_and_names_priority_five() {
    let plain = with_body("2505");
    let frame = decode_lane_frame(&plain).expect("frame");
    assert_eq!(frame.lane, Lane::DEFAULT);
    let spelled = with_body("a5053105");
    let explicit = decode_lane_frame(&spelled).expect("explicit default");
    assert_eq!(explicit.lane, Lane::DEFAULT);
}

#[test]
fn an_extension_other_than_the_mandatory_qos_is_refused() {
    // The frame header with the extension flag, and each way the extension can be wrong.
    for (name, header) in [
        ("priority 8", "a5053108"),
        ("priority 255", "a50531ff01"),
        ("not mandatory", "a5052102"),
        ("another id", "a5053202"),
        ("a chain", "a505b1024100"),
        ("an unknown extension", "a5054100"),
    ] {
        let bytes = with_body(header);
        assert_eq!(
            decode_lane_frame(&bytes),
            Err(Refusal::UnsupportedExtension),
            "{name}"
        );
    }
    let bytes = with_body("e6053108");
    assert_eq!(
        decode_lane_fragment(&bytes, None).err(),
        Some(FragmentError::Refused(Refusal::UnsupportedExtension))
    );
}

#[test]
fn a_value_the_extension_cannot_carry_is_refused_with_its_own_class() {
    // The extension is `31` and a value. A value over 32 bits, a padded value and a cut one are not a
    // priority above 7: the reader refuses them as a number, as it refuses a sequence number.
    for (name, header, class) in [
        ("over 32 bits", "a50531ffffffff1f", Refusal::Leb128Overflow),
        ("padded", "a505318000", Refusal::Leb128Noncanonical),
        ("cut after the id", "a50531", Refusal::Truncated),
        ("256", "a505318002", Refusal::UnsupportedExtension),
    ] {
        let bytes = with_body(header);
        assert_eq!(decode_lane_frame(&bytes), Err(class), "{name}");
    }
}

#[test]
fn a_header_with_no_body_or_a_reserved_flag_is_refused() {
    assert_eq!(
        decode_lane_frame(&unhex("2505")),
        Err(Refusal::MalformedMessage)
    );
    assert_eq!(
        decode_lane_frame(&with_body("6505")),
        Err(Refusal::MalformedMessage)
    );
    assert_eq!(
        decode_lane_fragment(&unhex("6605"), None).err(),
        Some(FragmentError::Refused(Refusal::MalformedMessage))
    );
    assert_eq!(
        decode_lane_frame(&with_body("0605")),
        Err(Refusal::UnsupportedMessage)
    );
}

#[test]
fn a_fragment_is_held_to_the_batch_the_peer_was_told() {
    let bytes = with_body("6605");
    assert!(decode_lane_fragment(&bytes, Some(6)).is_ok());
    assert_eq!(
        decode_lane_fragment(&bytes, Some(5)).err(),
        Some(FragmentError::Refused(Refusal::LengthExceedsBatch))
    );
}

#[test]
fn a_sequence_number_is_canonical_and_fits_32_bits() {
    // Five bytes of 0xff overflow 32 bits, and a padded zero is not canonical.
    assert!(decode_lane_frame(&with_body("25ffffffffff0f")).is_err());
    assert!(decode_lane_frame(&with_body("25ffffffff0f")).is_ok());
    assert!(decode_lane_frame(&with_body("258000")).is_err());
}

#[test]
fn the_lanes_are_sixteen_and_each_has_its_own_index() {
    let mut seen = [false; 16];
    for priority in 0..PRIORITIES {
        for reliable in [true, false] {
            let index = Lane { priority, reliable }.index();
            assert!(!seen[index], "{index} twice");
            seen[index] = true;
        }
    }
    assert!(seen.iter().all(|taken| *taken));
}
