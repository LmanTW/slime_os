// Host test for the z-serial framer. Each `[zenoh-exam] zserial` line is printed after its assertions passed, and
// `scripts/lib/zenoh_serial_frame_exam.py` judges them against `scripts/lib/zserial_wire.py`.

use std::string::String;
use std::vec::Vec;

const VECTORS: &str = include_str!("../../../scripts/lib/zserial_vectors.txt");

fn line(text: &str) {
    println!("[zenoh-exam] zserial {text}");
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::from("-");
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex")).collect()
}

fn framed(data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; MAX_WIRE];
    let length = encode(data, &mut out).expect("frame");
    out[..length].to_vec()
}

fn run_stream(name: &str, chunks: &[&[u8]]) {
    let mut receiver = Receiver::new();
    let mut delivered: Vec<Vec<u8>> = Vec::new();
    for chunk in chunks {
        receiver.push(chunk, |data| delivered.push(data.to_vec()));
    }
    let listed = if delivered.is_empty() {
        String::from("-")
    } else {
        delivered.iter().map(|data| hex(data)).collect::<Vec<_>>().join(",")
    };
    line(&format!("stream {name} {} {} {listed}", delivered.len(), receiver.dropped()));
}

#[test]
fn the_frame_exam() {
    let mut out = [0u8; MAX_WIRE];
    for row in VECTORS.lines().filter(|row| !row.trim().is_empty() && !row.starts_with('#')) {
        let fields: Vec<&str> = row.split_whitespace().collect();
        match fields[0] {
            "frame" => {
                let wire = framed(&unhex(fields[2]));
                assert_eq!(hex(&wire), fields[3], "frame {} differs from z-serial", fields[1]);
                line(&format!("frame {} {}", fields[1], hex(&wire)));
            }
            "decode" => {
                let wire = unhex(fields[2]);
                let stock_took = fields[3] == "ok";
                let stock_data = if stock_took { unhex(fields[4]) } else { Vec::new() };
                match decode(&wire, &mut out) {
                    Ok(length) => {
                        assert!(stock_took, "decode {} took a wire z-serial refused", fields[1]);
                        assert_eq!(&out[..length], &stock_data[..], "decode {} returned other data", fields[1]);
                        line(&format!("decode {} ok {}", fields[1], hex(&out[..length])));
                    }
                    Err(error) => {
                        assert!(!stock_took || stock_data.len() > MAX_DATA, "decode {} refused a wire z-serial took", fields[1]);
                        line(&format!("decode {} refused {}", fields[1], error.kind()));
                    }
                }
            }
            "limit" => {
                let length: usize = fields[2].parse().expect("length");
                let error = encode(&std::vec![0u8; length], &mut out).expect_err("over-long write");
                assert_eq!(error, Error::Size);
                line(&format!("limit {} refused {}", fields[1], error.kind()));
            }
            other => panic!("unknown vector line {other}"),
        }
    }

    let good = framed(&[0x11, 0x22, 0x00, 0x33]);
    let other = framed(&[0x00, 0x11, 0x00]);
    let mut bad_crc = good.clone();
    let at = bad_crc.len() - 2;
    bad_crc[at] ^= 0x01;
    let largest = framed(&[1u8; MAX_DATA]);

    run_stream("whole", &[&good]);
    let singles: Vec<[u8; 1]> = good.iter().map(|byte| [*byte]).collect();
    let singles: Vec<&[u8]> = singles.iter().map(|byte| &byte[..]).collect();
    run_stream("byte-at-a-time", &singles);
    run_stream("two-in-one-chunk", &[&[good.as_slice(), other.as_slice()].concat()]);
    run_stream("split-inside-a-run", &[&good[..3], &good[3..7], &good[7..]]);
    run_stream("garbage-then-frame", &[&[&[0x07, 0x07, 0x00][..], good.as_slice()].concat()]);
    let overrun: Vec<u8> = [std::vec![1u8; 1600], std::vec![0u8], good.clone()].concat();
    run_stream("overrun-then-frame", &[&overrun]);
    run_stream("leading-sentinels", &[&[&[0x00, 0x00][..], good.as_slice()].concat()]);
    run_stream("bad-crc-then-good", &[&[bad_crc.as_slice(), good.as_slice()].concat()]);
    run_stream("max-frame-whole", &[&largest]);
    let chunks: Vec<&[u8]> = largest.chunks(64).collect();
    run_stream("max-frame-64-byte-chunks", &chunks);
    run_stream("max-frame-then-small", &[&[largest.as_slice(), good.as_slice()].concat()]);
}
