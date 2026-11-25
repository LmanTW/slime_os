//! The lane a FRAME or a FRAGMENT belongs to.
//!
//! A stock peer keeps one sequence counter and one reassembly buffer for each pair of a priority (0 to 7) and
//! a reliability, and it names the pair in the transport header: the reliable flag, and for a priority other
//! than the default the transport QoS extension. This module reads that header. It is pure and calls
//! nothing: [`Lane`] says which pair a batch is for, and [`decode_lane_frame`] and [`decode_lane_fragment`]
//! return the sequence number and the body.
//!
//! What is accepted is what `zenoh-codec` 1.0.0 writes and nothing else. The default priority has no
//! extension. Any other priority is the mandatory extension `31 <priority>` with a priority of 0 to 7, and
//! it is the only extension. A link that did not negotiate the QoS unit extension never calls this module,
//! because upstream reads a priority other than the default only on a connection that negotiated it.
//! Upstream skips an unknown extension that is not mandatory and reads the priority from the low three bits
//! of the value. This decoder refuses both.

use super::fragment::{FragmentError, ID_FRAGMENT, is_fragment};
use super::{FLAG_BIT5, FLAG_BIT6, FLAG_Z, ID_FRAME, ID_MASK, Reader, Refusal};
use slime_proto::zenoh_profile as p;

/// The default priority, which upstream writes without an extension.
pub const DEFAULT_PRIORITY: u8 = 5;
/// The most priorities upstream names.
pub const PRIORITIES: u8 = 8;
/// The transport QoS extension: mandatory, id 1, a Z64 value that is the priority.
const EXT_QOS: u8 = 0x31;
const FLAG_MORE: u8 = FLAG_BIT6;

/// A pair of a priority and a reliability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lane {
    pub priority: u8,
    pub reliable: bool,
}

impl Lane {
    /// The lane of the first release: the default priority, reliable.
    pub const DEFAULT: Self = Self {
        priority: DEFAULT_PRIORITY,
        reliable: true,
    };

    /// The index of the lane among the 16: priority first, then reliable before best-effort.
    pub const fn index(self) -> usize {
        self.priority as usize * 2 + if self.reliable { 0 } else { 1 }
    }
}

/// One decoded FRAME header on a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneFrame<'a> {
    pub lane: Lane,
    pub sn: u32,
    /// The network messages, as the batch carries them. The caller reads them as it reads any FRAME.
    pub body: &'a [u8],
}

/// One decoded FRAGMENT on a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneFragment<'a> {
    pub lane: Lane,
    pub more: bool,
    pub sn: u32,
    pub data: &'a [u8],
}

/// Reads the extension chain of a FRAME or a FRAGMENT: nothing, or exactly the mandatory QoS extension. A
/// priority above 7, any other extension and a chain that goes on are refused as `unsupported-extension`.
/// A value that is cut, padded or wider than 32 bits is refused as the number it is: `truncated`,
/// `leb128-noncanonical` or `leb128-overflow`.
fn priority(reader: &mut Reader<'_>, header: u8) -> Result<u8, Refusal> {
    if header & FLAG_Z == 0 {
        return Ok(DEFAULT_PRIORITY);
    }
    if reader.u8()? != EXT_QOS {
        return Err(Refusal::UnsupportedExtension);
    }
    let value = reader.leb(p::LEB128_MAX_BITS)?;
    match u8::try_from(value) {
        Ok(priority) if priority < PRIORITIES => Ok(priority),
        _ => Err(Refusal::UnsupportedExtension),
    }
}

/// Whether the batch is a FRAME, whatever else it says.
pub const fn is_frame(header: u8) -> bool {
    header & ID_MASK == ID_FRAME
}

/// Decodes the header of one FRAME body. The network messages after it are not read here.
pub fn decode_lane_frame(body: &[u8]) -> Result<LaneFrame<'_>, Refusal> {
    let mut reader = Reader::new(body);
    let header = reader.u8()?;
    if !is_frame(header) {
        return Err(Refusal::UnsupportedMessage);
    }
    // Bit 6 of a FRAME header is reserved.
    if header & FLAG_MORE != 0 {
        return Err(Refusal::MalformedMessage);
    }
    let reliable = header & FLAG_BIT5 != 0;
    let sn = reader.leb(p::LEB128_MAX_BITS)?;
    let priority = priority(&mut reader, header)?;
    let rest = reader.take(reader.left())?;
    if rest.is_empty() {
        return Err(Refusal::MalformedMessage);
    }
    Ok(LaneFrame {
        lane: Lane { priority, reliable },
        sn,
        body: rest,
    })
}

/// Decodes one FRAGMENT body. With `batch`, the batch this side announced, a body longer than the batch less
/// the stream length is refused, as [`super::fragment::decode_fragment`] refuses it.
pub fn decode_lane_fragment(
    body: &[u8],
    batch: Option<usize>,
) -> Result<LaneFragment<'_>, FragmentError> {
    if let Some(batch) = batch
        && body.len() > batch.saturating_sub(super::STREAM_LENGTH_BYTES)
    {
        return Err(Refusal::LengthExceedsBatch.into());
    }
    let mut reader = Reader::new(body);
    let header = reader.u8().map_err(|_| Refusal::MalformedMessage)?;
    if !is_fragment(header) {
        return Err(Refusal::UnsupportedMessage.into());
    }
    let reliable = header & FLAG_BIT5 != 0;
    let sn = reader.leb(p::LEB128_MAX_BITS)?;
    let priority = priority(&mut reader, header)?;
    let data = reader.take(reader.left())?;
    if data.is_empty() {
        return Err(Refusal::MalformedMessage.into());
    }
    Ok(LaneFragment {
        lane: Lane { priority, reliable },
        more: header & FLAG_MORE != 0,
        sn,
        data,
    })
}

/// The lane a FRAGMENT body names, read without judging the rest of it. A body whose header, number or
/// extension cannot be read names none, and neither does a priority above 7. A caller that refuses a fragment
/// uses it to find the run the refusal ends.
pub fn peek_fragment_lane(body: &[u8]) -> Option<Lane> {
    let mut reader = Reader::new(body);
    let header = reader.u8().ok()?;
    if !is_fragment(header) {
        return None;
    }
    reader.leb(p::LEB128_MAX_BITS).ok()?;
    let priority = priority(&mut reader, header).ok()?;
    Some(Lane {
        priority,
        reliable: header & FLAG_BIT5 != 0,
    })
}

const _: () = assert!(ID_FRAGMENT == 0x06);

#[cfg(test)]
#[path = "lane_tests.rs"]
mod tests;
