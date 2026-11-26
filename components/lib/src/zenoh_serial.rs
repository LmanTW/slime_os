//! The z-serial frame of `zenoh-link-serial` 1.0.0: a COBS body ended by the sentinel 0x00.
//!
//! The body is a 2-byte little-endian length, the data and a 4-byte little-endian CRC. The CRC is not the standard CRC-32: it
//! runs the polynomial 0x04C11DB7 through a reflected loop and inverts the accumulator at both ends. This module does no I/O.
//! `scripts/lib/zserial_wire.py` is the host reference, and `scripts/lib/zenoh_serial_frame_exam.py` judges what the test prints.
//!
//! The data bound is [`MAX_DATA`] in both directions. The stock decoder takes more than the stock writer writes, and the reader
//! here refuses a length field above the bound before it compares the length with the body.

/// The most data bytes in one frame: the stock writer's bound.
pub const MAX_DATA: usize = 1500;
/// The stock read loop gives up on a run of this many bytes with no sentinel.
pub const MAX_WIRE: usize = 1516;
const LENGTH_BYTES: usize = 2;
const CRC_BYTES: usize = 4;
const MAX_BODY: usize = LENGTH_BYTES + MAX_DATA + CRC_BYTES;
const SENTINEL: u8 = 0;
const POLYNOMIAL: u32 = 0x04C1_1DB7;

/// Why a frame was refused. [`Error::kind`] gives the class name the exam uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No trailing sentinel, or a sentinel inside the frame.
    Sentinel,
    /// A zero code byte, a run past the end or a zero inside a run.
    Cobs,
    /// A body smaller than a length and a CRC.
    Short,
    /// The length field does not match the body.
    Length,
    /// The CRC does not match the data.
    Crc,
    /// More data than [`MAX_DATA`], or more wire than [`MAX_WIRE`].
    Size,
    /// The caller's buffer is too small.
    Space,
}

impl Error {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Sentinel => "sentinel",
            Self::Cobs => "cobs",
            Self::Short => "short",
            Self::Length => "length",
            Self::Crc => "crc",
            Self::Size => "size",
            Self::Space => "space",
        }
    }
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut remainder = n as u32;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 1 == 1 {
                POLYNOMIAL ^ (remainder >> 1)
            } else {
                remainder >> 1
            };
            bit += 1;
        }
        table[n] = remainder;
        n += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

pub fn crc(data: &[u8]) -> u32 {
    let mut accumulator = 0xFFFF_FFFFu32;
    for &byte in data {
        accumulator = (accumulator >> 8) ^ CRC_TABLE[((accumulator & 0xFF) as u8 ^ byte) as usize];
    }
    !accumulator
}

/// Writes one frame for `data` into `out` and returns its length, sentinel included.
pub fn encode(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if data.len() > MAX_DATA {
        return Err(Error::Size);
    }
    let mut body = [0u8; MAX_BODY];
    let body_len = LENGTH_BYTES + data.len() + CRC_BYTES;
    body[..LENGTH_BYTES].copy_from_slice(&(data.len() as u16).to_le_bytes());
    body[LENGTH_BYTES..LENGTH_BYTES + data.len()].copy_from_slice(data);
    body[LENGTH_BYTES + data.len()..body_len].copy_from_slice(&crc(data).to_le_bytes());
    // One code byte for each 254 body bytes, one for the last block, and the sentinel.
    if out.len() < body_len + body_len / 254 + 2 {
        return Err(Error::Space);
    }
    let mut code_at = 0;
    let mut at = 1;
    let mut code = 1u8;
    for &byte in &body[..body_len] {
        if byte == 0 {
            out[code_at] = code;
            code_at = at;
            at += 1;
            code = 1;
        } else {
            out[at] = byte;
            at += 1;
            code += 1;
            if code == 255 {
                out[code_at] = code;
                code_at = at;
                at += 1;
                code = 1;
            }
        }
    }
    out[code_at] = code;
    out[at] = SENTINEL;
    Ok(at + 1)
}

/// Reads one whole frame, a COBS body and its one trailing sentinel. Writes the data into `out` and returns its length.
pub fn decode(wire: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if wire.len() > MAX_WIRE {
        return Err(Error::Size);
    }
    let Some((&last, encoded)) = wire.split_last() else {
        return Err(Error::Sentinel);
    };
    if last != SENTINEL || encoded.contains(&SENTINEL) {
        return Err(Error::Sentinel);
    }
    let mut body = [0u8; MAX_WIRE];
    let mut body_len = 0;
    let mut index = 0;
    while index < encoded.len() {
        let code = encoded[index] as usize;
        let end = index + code;
        if end > encoded.len() {
            return Err(Error::Cobs);
        }
        let run = &encoded[index + 1..end];
        body[body_len..body_len + run.len()].copy_from_slice(run);
        body_len += run.len();
        index = end;
        if code != 255 && index < encoded.len() {
            body[body_len] = 0;
            body_len += 1;
        }
    }
    if body_len < LENGTH_BYTES + CRC_BYTES {
        return Err(Error::Short);
    }
    let length = u16::from_le_bytes([body[0], body[1]]) as usize;
    if length > MAX_DATA {
        return Err(Error::Size);
    }
    if LENGTH_BYTES + length + CRC_BYTES != body_len {
        return Err(Error::Length);
    }
    let data = &body[LENGTH_BYTES..LENGTH_BYTES + length];
    let mut stored = [0u8; CRC_BYTES];
    stored.copy_from_slice(&body[LENGTH_BYTES + length..body_len]);
    if u32::from_le_bytes(stored) != crc(data) {
        return Err(Error::Crc);
    }
    if out.len() < length {
        return Err(Error::Space);
    }
    out[..length].copy_from_slice(data);
    Ok(length)
}

/// Splits a byte stream into frames. A run that reaches a sentinel is one frame: it is delivered if it decodes and counted as a
/// drop once if it does not. A run of [`MAX_WIRE`] bytes with no sentinel is discarded up to and including the next sentinel,
/// and counted once.
pub struct Receiver {
    held: [u8; MAX_WIRE],
    len: usize,
    discarding: bool,
    dropped: u32,
}

impl Receiver {
    pub const fn new() -> Self {
        Self {
            held: [0; MAX_WIRE],
            len: 0,
            discarding: false,
            dropped: 0,
        }
    }

    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    pub fn push(&mut self, bytes: &[u8], mut deliver: impl FnMut(&[u8])) {
        let mut data = [0u8; MAX_DATA];
        for &byte in bytes {
            if self.discarding {
                if byte == SENTINEL {
                    self.discarding = false;
                    self.dropped += 1;
                }
                continue;
            }
            if byte == SENTINEL {
                // `len` is at most `MAX_WIRE - 1`, so the sentinel fits.
                self.held[self.len] = SENTINEL;
                let wire_len = self.len + 1;
                self.len = 0;
                match decode(&self.held[..wire_len], &mut data) {
                    Ok(length) => deliver(&data[..length]),
                    Err(_) => self.dropped += 1,
                }
                continue;
            }
            self.held[self.len] = byte;
            self.len += 1;
            if self.len >= MAX_WIRE {
                self.len = 0;
                self.discarding = true;
            }
        }
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

// The exam's test sits at the top of this module, so its name is `zenoh_serial::the_frame_exam`, the one the judge pins.
#[cfg(test)]
include!("zenoh_serial_tests.rs");
