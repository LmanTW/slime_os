//! Classic CDR (`CDR_LE`) for `slime_demo_msgs/msg/Counter { uint32 sequence; int32 value; }`.
//!
//! Wire form: encapsulation header `00 01 00 00` (representation id and options are
//! big-endian as written), then `sequence` as u32 and `value` as i32, both little-endian.

/// Encapsulation header: representation id 0x0001 (`CDR_LE`), options 0x0000.
const ENCAPSULATION: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
const BODY_BYTES: usize = 8;

/// Serialized size of one `Counter`, equal to the demo contract's `maxPayloadBytes`.
pub const MAX_SERIALIZED_BYTES: usize = ENCAPSULATION.len() + BODY_BYTES;

/// Extra bytes up to this count after a complete message are reported as
/// [`CdrError::TrailingBytes`]; a longer input is [`CdrError::OverMax`]. Both
/// are decided after the encapsulation and before any field is read.
const TRAILING_BYTES_LIMIT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrError {
    /// The output buffer is shorter than [`MAX_SERIALIZED_BYTES`].
    BufferTooSmall,
    /// Fewer than 4 bytes: no complete encapsulation header.
    TruncatedHeader,
    /// A valid header followed by fewer than 8 body bytes.
    TruncatedBody,
    /// A complete message followed by 1 to 3 extra bytes.
    TrailingBytes,
    /// Representation id 0x0000, the big-endian `CDR_BE` encapsulation.
    BigEndianEncapsulation,
    /// Any representation id other than 0x0001 and 0x0000.
    UnknownEncapsulation,
    /// Options other than 0x0000.
    NonzeroOptions,
    /// A complete message followed by 4 or more extra bytes.
    OverMax,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counter {
    pub sequence: u32,
    pub value: i32,
}

impl Counter {
    /// Writes the serialized message to the front of `out` and returns its length.
    /// `out` is untouched when it is shorter than [`MAX_SERIALIZED_BYTES`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CdrError> {
        let dst = out
            .get_mut(..MAX_SERIALIZED_BYTES)
            .ok_or(CdrError::BufferTooSmall)?;
        let [h0, h1, h2, h3] = ENCAPSULATION;
        let [s0, s1, s2, s3] = self.sequence.to_le_bytes();
        let [v0, v1, v2, v3] = self.value.to_le_bytes();
        dst.copy_from_slice(&[h0, h1, h2, h3, s0, s1, s2, s3, v0, v1, v2, v3]);
        Ok(MAX_SERIALIZED_BYTES)
    }

    /// Parses exactly one serialized message. The length and the encapsulation are
    /// judged before any field is read.
    pub fn decode(bytes: &[u8]) -> Result<Self, CdrError> {
        let (header, rest) = bytes
            .split_first_chunk::<4>()
            .ok_or(CdrError::TruncatedHeader)?;
        let [rep_hi, rep_lo, opt_hi, opt_lo] = *header;
        match u16::from_be_bytes([rep_hi, rep_lo]) {
            0x0001 => {}
            0x0000 => return Err(CdrError::BigEndianEncapsulation),
            _ => return Err(CdrError::UnknownEncapsulation),
        }
        if u16::from_be_bytes([opt_hi, opt_lo]) != 0 {
            return Err(CdrError::NonzeroOptions);
        }
        let (body, extra) = rest
            .split_first_chunk::<BODY_BYTES>()
            .ok_or(CdrError::TruncatedBody)?;
        if !extra.is_empty() {
            return Err(if extra.len() <= TRAILING_BYTES_LIMIT {
                CdrError::TrailingBytes
            } else {
                CdrError::OverMax
            });
        }
        let [s0, s1, s2, s3, v0, v1, v2, v3] = *body;
        Ok(Self {
            sequence: u32::from_le_bytes([s0, s1, s2, s3]),
            value: i32::from_le_bytes([v0, v1, v2, v3]),
        })
    }
}

#[cfg(test)]
#[path = "ros_cdr/tests.rs"]
mod tests;
