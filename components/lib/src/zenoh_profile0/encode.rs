//! Zenoh Profile 0 encoder.
//!
//! Every function writes one batch body (no stream length prefix) into
//! caller-provided storage and returns the number of bytes written, or an
//! [`EncodeError`]. A batch longer than `MAX_BATCH_BYTES` or than the storage
//! is refused, never truncated, and an input the decoder would refuse is
//! refused here with the matching class. Nothing allocates.

use super::{
    ATTACHMENT_GID_LEN_AT, Bounds, EXT_ATTACHMENT, EXT_QOS_UNIT, EXT_WIRE_EXPR, FLAG_BIT5,
    FLAG_BIT6, FLAG_Z, GID_BYTES, ID_CLOSE, ID_D_SUBSCRIBER, ID_DECLARE, ID_FRAME, ID_INIT,
    ID_KEEP_ALIVE, ID_OPEN, ID_PUSH, ID_PUT, MAX_ATTACHMENT_BYTES, MAX_BATCH_BYTES,
    MAX_COOKIE_BYTES, Mapping, Refusal, STREAM_LENGTH_BYTES, U_SUBSCRIBER_HEADER,
    WIRE_EXPR_FLAG_NAMED, WIRE_EXPR_FLAG_SENDER, key_expression,
};
use slime_proto::zenoh_profile as p;

const RESOLUTION: u8 = p::DEFAULT_RESOLUTION as u8;
const VERSION: u8 = p::PROTOCOL_VERSION as u8;
const WHATAMI_PEER: u8 = p::WHATAMI_PEER as u8;
const WHATAMI_CLIENT: u8 = p::WHATAMI_CLIENT as u8;
const GID_LEN_BYTE: u8 = GID_BYTES as u8;
/// Batch size an INIT states by omitting its size parameters.
const DEFAULT_BATCH_SIZE: u16 = u16::MAX;
/// The scope of every key expression the profile carries is the global one.
const GLOBAL_SCOPE: u32 = 0;

/// Why the encoder refuses an input or cannot finish a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The caller's storage is shorter than the batch.
    OutputTooSmall,
    /// The batch would exceed `MAX_BATCH_BYTES`.
    BatchTooLarge,
    /// A ZID is empty or over 16 bytes.
    ZidLength,
    /// A ZID whose last byte is zero, which includes the all-zero ID. Upstream holds a ZID as a
    /// little-endian integer, so it drops trailing zero bytes and refuses zero: such an ID has no
    /// wire form it would reproduce.
    ZidNotCanonical,
    /// An INIT batch size of zero.
    BatchSizeZero,
    CookieEmpty,
    CookieTooLong,
    /// A lease of zero, or one that does not fit 32 bits in its unit.
    LeaseOutOfRange,
    /// A CLOSE reason the decoder does not know.
    CloseReasonUnknown,
    KeyTooLong,
    /// An empty key, or one the decoder refuses as an invalid key expression.
    InvalidKey,
    /// A key with a `*` or `$` chunk.
    WildcardKey,
    /// An attachment that is not exactly `MAX_ATTACHMENT_BYTES` long.
    AttachmentLength,
    /// An attachment whose GID is not 16 bytes, or whose GID length byte is not 16.
    AttachmentGid,
    PayloadTooLong,
    /// A FRAME with no network message.
    EmptyFrame,
    /// A stream length of zero or over `MAX_BATCH_BYTES`.
    StreamLength,
}

/// Append-only cursor over caller storage; `len` only advances on success.
struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
    cap: usize,
}

impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self::with_cap(out, MAX_BATCH_BYTES)
    }

    fn with_cap(out: &'a mut [u8], cap: usize) -> Self {
        Self { out, len: 0, cap }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(EncodeError::BatchTooLarge)?;
        if end > self.cap {
            return Err(EncodeError::BatchTooLarge);
        }
        let slot = self
            .out
            .get_mut(self.len..end)
            .ok_or(EncodeError::OutputTooSmall)?;
        slot.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), EncodeError> {
        self.put(&[value])
    }

    /// A canonical LEB128 unsigned integer.
    fn leb(&mut self, value: u32) -> Result<(), EncodeError> {
        let mut rest = value;
        let mut bytes = [0u8; 5];
        let mut count = 0;
        for slot in &mut bytes {
            let low = (rest & 0x7F) as u8;
            rest >>= 7;
            count += 1;
            if rest == 0 {
                *slot = low;
                break;
            }
            *slot = low | 0x80;
        }
        self.put(bytes.get(..count).ok_or(EncodeError::BatchTooLarge)?)
    }

    fn prefixed(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let length = u32::try_from(bytes.len()).map_err(|_| EncodeError::BatchTooLarge)?;
        self.leb(length)?;
        self.put(bytes)
    }
}

fn check_zid(zid: &[u8]) -> Result<u8, EncodeError> {
    if zid.is_empty() || zid.len() > p::MAX_ZID_BYTES {
        return Err(EncodeError::ZidLength);
    }
    if zid.last() == Some(&0) {
        return Err(EncodeError::ZidNotCanonical);
    }
    u8::try_from(zid.len().saturating_sub(1)).map_err(|_| EncodeError::ZidLength)
}

fn check_cookie(cookie: &[u8]) -> Result<(), EncodeError> {
    if cookie.is_empty() {
        Err(EncodeError::CookieEmpty)
    } else if cookie.len() > MAX_COOKIE_BYTES {
        Err(EncodeError::CookieTooLong)
    } else {
        Ok(())
    }
}

/// The decoder's key-expression rule, applied to the bytes that would be sent.
fn check_key(key: &str, max: usize) -> Result<&[u8], EncodeError> {
    if key.len() > max {
        return Err(EncodeError::KeyTooLong);
    }
    if key.is_empty() {
        return Err(EncodeError::InvalidKey);
    }
    match key_expression(key.as_bytes()) {
        Ok(valid) => Ok(valid.as_bytes()),
        Err(Refusal::WildcardKeyexpr) => Err(EncodeError::WildcardKey),
        Err(_) => Err(EncodeError::InvalidKey),
    }
}

fn init(
    out: &mut [u8],
    zid: &[u8],
    batch_size: u16,
    cookie: Option<&[u8]>,
    qos: bool,
    whatami: u8,
) -> Result<usize, EncodeError> {
    let zid_code = check_zid(zid)?;
    if batch_size == 0 {
        return Err(EncodeError::BatchSizeZero);
    }
    if let Some(cookie) = cookie {
        check_cookie(cookie)?;
    }
    let sized = batch_size != DEFAULT_BATCH_SIZE;
    let mut header = ID_INIT;
    if cookie.is_some() {
        header |= FLAG_BIT5;
    }
    if sized {
        header |= FLAG_BIT6;
    }
    if qos {
        header |= FLAG_Z;
    }
    let mut writer = Writer::new(out);
    writer.byte(header)?;
    writer.byte(VERSION)?;
    writer.byte((zid_code << 4) | whatami)?;
    writer.put(zid)?;
    if sized {
        writer.byte(RESOLUTION)?;
        writer.put(&batch_size.to_le_bytes())?;
    }
    if let Some(cookie) = cookie {
        writer.prefixed(cookie)?;
    }
    if qos {
        writer.byte(EXT_QOS_UNIT)?;
    }
    Ok(writer.len)
}

/// INIT_SYN as a peer. A `batch_size` of `u16::MAX` is the default and is sent
/// by omitting the size parameters.
pub fn init_syn(out: &mut [u8], zid: &[u8], batch_size: u16) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, None, false, WHATAMI_PEER)
}

/// INIT_SYN as a client: the peer form with `whatami` 2 and no other byte different.
pub fn init_syn_client(out: &mut [u8], zid: &[u8], batch_size: u16) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, None, false, WHATAMI_CLIENT)
}

/// INIT_SYN as a client that offers the QoS unit extension.
pub fn init_syn_client_qos(
    out: &mut [u8],
    zid: &[u8],
    batch_size: u16,
) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, None, true, WHATAMI_CLIENT)
}

/// INIT_SYN that offers the QoS unit extension, one byte after the rest of the message.
pub fn init_syn_qos(out: &mut [u8], zid: &[u8], batch_size: u16) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, None, true, WHATAMI_PEER)
}

/// INIT_ACK as a peer, carrying the 1..=64 byte cookie.
pub fn init_ack(
    out: &mut [u8],
    zid: &[u8],
    batch_size: u16,
    cookie: &[u8],
) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, Some(cookie), false, WHATAMI_PEER)
}

/// INIT_ACK that accepts the peer's QoS offer, one byte after the rest of the message.
pub fn init_ack_qos(
    out: &mut [u8],
    zid: &[u8],
    batch_size: u16,
    cookie: &[u8],
) -> Result<usize, EncodeError> {
    init(out, zid, batch_size, Some(cookie), true, WHATAMI_PEER)
}

fn open(
    out: &mut [u8],
    ack: bool,
    lease_ms: u64,
    initial_sn: u32,
    cookie: Option<&[u8]>,
) -> Result<usize, EncodeError> {
    if lease_ms == 0 {
        return Err(EncodeError::LeaseOutOfRange);
    }
    if let Some(cookie) = cookie {
        check_cookie(cookie)?;
    }
    let seconds = lease_ms.is_multiple_of(1000);
    let lease = if seconds { lease_ms / 1000 } else { lease_ms };
    let lease = u32::try_from(lease).map_err(|_| EncodeError::LeaseOutOfRange)?;
    let mut header = ID_OPEN;
    if ack {
        header |= FLAG_BIT5;
    }
    if seconds {
        header |= FLAG_BIT6;
    }
    let mut writer = Writer::new(out);
    writer.byte(header)?;
    writer.leb(lease)?;
    writer.leb(initial_sn)?;
    if let Some(cookie) = cookie {
        writer.prefixed(cookie)?;
    }
    Ok(writer.len)
}

/// OPEN_SYN. The lease is sent in seconds when `lease_ms` divides evenly and in
/// milliseconds otherwise.
pub fn open_syn(
    out: &mut [u8],
    lease_ms: u64,
    initial_sn: u32,
    cookie: &[u8],
) -> Result<usize, EncodeError> {
    open(out, false, lease_ms, initial_sn, Some(cookie))
}

/// OPEN_ACK, with the lease unit chosen as for [`open_syn`].
pub fn open_ack(out: &mut [u8], lease_ms: u64, initial_sn: u32) -> Result<usize, EncodeError> {
    open(out, true, lease_ms, initial_sn, None)
}

/// CLOSE. `session` closes the whole session rather than only the link.
pub fn close(out: &mut [u8], reason: u8, session: bool) -> Result<usize, EncodeError> {
    if u32::from(reason) > p::CLOSE_CONNECTION_TO_SELF {
        return Err(EncodeError::CloseReasonUnknown);
    }
    let mut writer = Writer::new(out);
    writer.byte(ID_CLOSE | if session { FLAG_BIT5 } else { 0 })?;
    writer.byte(reason)?;
    Ok(writer.len)
}

/// KEEP_ALIVE: the single byte `0x04`.
pub fn keep_alive(out: &mut [u8]) -> Result<usize, EncodeError> {
    let mut writer = Writer::new(out);
    writer.byte(ID_KEEP_ALIVE)?;
    Ok(writer.len)
}

/// The 33-byte `rmw_zenoh` attachment: sequence number, source timestamp and a
/// 16-byte GID behind its length byte.
pub fn attachment(
    sequence: i64,
    timestamp: i64,
    gid: &[u8],
) -> Result<[u8; MAX_ATTACHMENT_BYTES], EncodeError> {
    if gid.len() != GID_BYTES {
        return Err(EncodeError::AttachmentGid);
    }
    let mut raw = [0u8; MAX_ATTACHMENT_BYTES];
    let bytes = sequence
        .to_le_bytes()
        .into_iter()
        .chain(timestamp.to_le_bytes())
        .chain([GID_LEN_BYTE])
        .chain(gid.iter().copied());
    for (slot, byte) in raw.iter_mut().zip(bytes) {
        *slot = byte;
    }
    Ok(raw)
}

fn declare_subscriber(
    writer: &mut Writer<'_>,
    id: u32,
    mapping: Mapping,
    key: &str,
    bounds: Bounds,
) -> Result<(), EncodeError> {
    let key = check_key(key, bounds.key)?;
    let mut header = ID_D_SUBSCRIBER | FLAG_BIT5;
    if mapping == Mapping::Sender {
        header |= FLAG_BIT6;
    }
    writer.byte(ID_DECLARE)?;
    writer.byte(header)?;
    writer.leb(id)?;
    writer.leb(GLOBAL_SCOPE)?;
    writer.prefixed(key)
}

fn undeclare_subscriber(
    writer: &mut Writer<'_>,
    id: u32,
    mapping: Mapping,
    key: &str,
    bounds: Bounds,
) -> Result<(), EncodeError> {
    let key = check_key(key, bounds.key)?;
    let mut flags = WIRE_EXPR_FLAG_NAMED;
    if mapping == Mapping::Sender {
        flags |= WIRE_EXPR_FLAG_SENDER;
    }
    // The ZBuf is <flags><scope:z16><raw suffix>; the suffix has no length of its own.
    let inner = 2usize
        .checked_add(key.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(EncodeError::KeyTooLong)?;
    writer.byte(ID_DECLARE)?;
    writer.byte(U_SUBSCRIBER_HEADER)?;
    writer.leb(id)?;
    writer.byte(EXT_WIRE_EXPR)?;
    writer.leb(inner)?;
    writer.byte(flags)?;
    writer.leb(GLOBAL_SCOPE)?;
    writer.put(key)
}

/// Refuses a Put the decoder would refuse: a key that is not a valid key expression within the bounds,
/// an attachment that is not the 33-byte form, or a payload over the bound.
pub fn validate_put(
    key: &str,
    attachment: &[u8],
    payload_len: usize,
    bounds: &Bounds,
) -> Result<(), EncodeError> {
    check_key(key, bounds.key)?;
    if attachment.len() != MAX_ATTACHMENT_BYTES {
        return Err(EncodeError::AttachmentLength);
    }
    if attachment.get(ATTACHMENT_GID_LEN_AT) != Some(&GID_LEN_BYTE) {
        return Err(EncodeError::AttachmentGid);
    }
    if payload_len > bounds.payload {
        return Err(EncodeError::PayloadTooLong);
    }
    Ok(())
}

fn push_put(
    writer: &mut Writer<'_>,
    mapping: Mapping,
    key: &str,
    attachment: &[u8],
    payload: &[u8],
    bounds: Bounds,
) -> Result<(), EncodeError> {
    validate_put(key, attachment, payload.len(), &bounds)?;
    let key = check_key(key, bounds.key)?;
    let mut header = ID_PUSH | FLAG_BIT5;
    if mapping == Mapping::Sender {
        header |= FLAG_BIT6;
    }
    writer.byte(header)?;
    writer.leb(GLOBAL_SCOPE)?;
    writer.prefixed(key)?;
    writer.byte(ID_PUT | FLAG_Z)?;
    writer.byte(EXT_ATTACHMENT)?;
    writer.prefixed(attachment)?;
    writer.prefixed(payload)
}

/// A reliable FRAME under construction. A network message that fails leaves
/// the frame as it was before the call.
pub struct FrameEncoder<'a> {
    writer: Writer<'a>,
    messages: usize,
    bounds: Bounds,
}

impl<'a> FrameEncoder<'a> {
    /// Starts a reliable FRAME with sequence number `sn` in `out`.
    pub fn new(out: &'a mut [u8], sn: u32) -> Result<Self, EncodeError> {
        Self::with_bounds(out, sn, Bounds::DEMO)
    }

    /// Starts a reliable FRAME that may be as large as `bounds` says.
    pub fn with_bounds(out: &'a mut [u8], sn: u32, bounds: Bounds) -> Result<Self, EncodeError> {
        let mut writer = Writer::with_cap(out, bounds.batch);
        writer.byte(ID_FRAME | FLAG_BIT5)?;
        writer.leb(sn)?;
        Ok(Self {
            writer,
            messages: 0,
            bounds,
        })
    }

    fn message(
        &mut self,
        write: impl FnOnce(&mut Writer<'a>) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        let mark = self.writer.len;
        match write(&mut self.writer) {
            Ok(()) => {
                self.messages += 1;
                Ok(())
            }
            Err(error) => {
                self.writer.len = mark;
                Err(error)
            }
        }
    }

    pub fn declare_subscriber(
        &mut self,
        id: u32,
        mapping: Mapping,
        key: &str,
    ) -> Result<(), EncodeError> {
        let bounds = self.bounds;
        self.message(|writer| declare_subscriber(writer, id, mapping, key, bounds))
    }

    pub fn undeclare_subscriber(
        &mut self,
        id: u32,
        mapping: Mapping,
        key: &str,
    ) -> Result<(), EncodeError> {
        let bounds = self.bounds;
        self.message(|writer| undeclare_subscriber(writer, id, mapping, key, bounds))
    }

    /// A PUSH carrying a Put with the 33-byte attachment and a payload of at
    /// most `MAX_PAYLOAD_BYTES`.
    pub fn push_put(
        &mut self,
        mapping: Mapping,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
    ) -> Result<(), EncodeError> {
        let bounds = self.bounds;
        self.message(|writer| push_put(writer, mapping, key, attachment, payload, bounds))
    }

    /// The batch length, once at least one network message is in the frame.
    pub fn finish(self) -> Result<usize, EncodeError> {
        if self.messages == 0 {
            return Err(EncodeError::EmptyFrame);
        }
        Ok(self.writer.len)
    }
}

/// The 2-byte little-endian stream length prefix for a batch of `batch_len`.
pub fn stream_prefix(batch_len: usize) -> Result<[u8; STREAM_LENGTH_BYTES], EncodeError> {
    stream_prefix_max(batch_len, MAX_BATCH_BYTES)
}

/// The stream length of a batch body of `batch_len` bytes, none longer than `max`.
pub fn stream_prefix_max(
    batch_len: usize,
    max: usize,
) -> Result<[u8; STREAM_LENGTH_BYTES], EncodeError> {
    if batch_len == 0 || batch_len > max {
        return Err(EncodeError::StreamLength);
    }
    let length = u16::try_from(batch_len).map_err(|_| EncodeError::StreamLength)?;
    Ok(length.to_le_bytes())
}

/// Copies `batch` behind its stream length prefix and returns the bytes written.
pub fn stream_batch(out: &mut [u8], batch: &[u8]) -> Result<usize, EncodeError> {
    stream_batch_max(out, batch, MAX_BATCH_BYTES)
}

/// Copies `batch`, no longer than `max`, behind its stream length prefix.
pub fn stream_batch_max(out: &mut [u8], batch: &[u8], max: usize) -> Result<usize, EncodeError> {
    let prefix = stream_prefix_max(batch.len(), max)?;
    let total = STREAM_LENGTH_BYTES + batch.len();
    let (head, body) = out
        .get_mut(..total)
        .and_then(|slot| slot.split_first_chunk_mut::<STREAM_LENGTH_BYTES>())
        .ok_or(EncodeError::OutputTooSmall)?;
    *head = prefix;
    body.copy_from_slice(batch);
    Ok(total)
}

#[cfg(test)]
#[path = "encode_tests.rs"]
mod tests;
